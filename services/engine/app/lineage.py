from __future__ import annotations

import hashlib
import html
import io
import os
import time
from typing import Any

import networkx as nx
from PIL import Image, ImageDraw, ImageFont


NODE_KINDS = {"Source", "Transform", "Store", "SinkResponse", "SinkLog", "SinkThirdParty", "SinkClientStorage", "Route", "Controller", "Finding"}
SINK_KIND = {
    "log": "SinkLog", "response": "SinkResponse", "database": "Store", "third_party": "SinkThirdParty",
    "client_storage": "SinkClientStorage", "http_transport": "SinkThirdParty", "error": "SinkResponse",
    "unauthenticated_route": "SinkResponse", "weak_hash": "Transform", "hardcoded_secret": "Transform",
}
COLORS = {
    "Source": "#2dd4bf", "Transform": "#818cf8", "Store": "#f87171", "SinkResponse": "#f87171",
    "SinkLog": "#f87171", "SinkThirdParty": "#fbbf24", "SinkClientStorage": "#fbbf24",
    "Route": "#818cf8", "Controller": "#818cf8", "Finding": "#fbbf24",
}


def _node_id(scan_id: str, kind: str, key: str) -> str:
    digest = hashlib.sha256(f"{scan_id}\0{kind}\0{key}".encode()).hexdigest()[:20]
    return f"{scan_id}:{digest}"


def build_lineage(scan: dict) -> dict:
    scan_id = str(scan["id"])
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def add_node(kind: str, key: str, properties: dict[str, Any]) -> str:
        identifier = _node_id(scan_id, kind, key)
        nodes.setdefault(identifier, {"id": identifier, "kind": kind, "scan_id": scan_id, "properties": properties})
        return identifier

    def add_edge(source: str, target: str, *, sanitization: str, erasure_path: str, relationship: str = "FLOWS_TO") -> None:
        edge_key = (source, target, relationship)
        edges.setdefault(edge_key, {
            "id": _node_id(scan_id, relationship, source + target), "source": source, "target": target,
            "type": relationship, "scan_id": scan_id,
            "properties": {"sanitization": sanitization, "erasure_path": erasure_path},
        })

    for finding in scan.get("findings", []):
        category = finding.get("pii_category", "other")
        source_step = next((step for step in finding.get("taint_path", []) if step.get("kind") == "source"), {})
        source_file = source_step.get("file", finding.get("file", ""))
        source_line = int(source_step.get("line", finding.get("line", 1)))
        source = add_node("Source", f"{source_file}:{source_line}:{category}", {
            "category": category, "file": source_file, "line": source_line, "label": f"{category} source",
        })
        path_nodes = [source]

        route_value = finding.get("route")
        if route_value:
            route = add_node("Route", f"{finding.get('file')}:{route_value}", {
                "route": route_value, "file": finding.get("file", ""), "line": int(finding.get("line", 1)), "label": route_value,
            })
            path_nodes.append(route)
        controller_step = next((step for step in finding.get("taint_path", []) if step.get("kind") == "controller"), None)
        if controller_step or route_value:
            controller_file = (controller_step or {}).get("file", finding.get("file", ""))
            controller = add_node("Controller", f"{controller_file}:{finding.get('line', 1)}", {
                "file": controller_file, "line": int(finding.get("line", 1)),
                "name": (controller_step or {}).get("value", "controller"), "label": (controller_step or {}).get("value", "controller"),
            })
            path_nodes.append(controller)

        sink_kind = SINK_KIND.get(finding.get("sink_type", ""), "Transform")
        sink_key = f"{finding.get('file')}:{finding.get('line')}:{finding.get('sink_type')}"
        sink_properties = {
            "file": finding.get("file", ""), "line": int(finding.get("line", 1)),
            "sink_type": finding.get("sink_type", ""), "category": category,
            "label": finding.get("sink_type", "sink"),
        }
        if sink_kind == "Store":
            sink_properties["encrypted"] = finding.get("rule_id") != "PL003"
            sink_properties["column"] = finding.get("db_column") or "unknown"
        sink = add_node(sink_kind, sink_key, sink_properties)
        path_nodes.append(sink)
        finding_node = add_node("Finding", finding.get("id", sink_key), {
            "finding_id": finding.get("id", ""), "rule_id": finding.get("rule_id", ""),
            "severity": finding.get("severity", "low"), "dpdp_section": finding.get("dpdp_section", ""),
            "file": finding.get("file", ""), "line": int(finding.get("line", 1)),
            "title": finding.get("title", "Finding"), "label": f"{finding.get('rule_id', 'PL')} {finding.get('severity', 'low')}",
        })

        erasure = "absent" if finding.get("rule_id") == "PL010" else "present"
        sanitization = "auth_gated" if route_value and not finding.get("unauthenticated") else "none"
        for left, right in zip(path_nodes, path_nodes[1:]):
            add_edge(left, right, sanitization=sanitization, erasure_path=erasure)
        add_edge(sink, finding_node, sanitization="none", erasure_path=erasure, relationship="HAS_FINDING")

    return {"scan_id": scan_id, "nodes": list(nodes.values()), "edges": list(edges.values()), "backend": "networkx"}


class LineageStore:
    def __init__(self) -> None:
        self.graphs: dict[str, dict] = {}
        self.networkx: dict[str, nx.MultiDiGraph] = {}
        self.driver = None
        self.last_driver_attempt = 0.0

    def _driver(self):
        if self.driver:
            return self.driver
        if time.monotonic() - self.last_driver_attempt < 5:
            return None
        self.last_driver_attempt = time.monotonic()
        uri = os.getenv("NEO4J_URI", "").strip()
        if not uri:
            return None
        try:
            from neo4j import GraphDatabase

            self.driver = GraphDatabase.driver(uri, auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "")), connection_timeout=2, max_transaction_retry_time=1)
            self.driver.verify_connectivity()
        except Exception:
            if self.driver:
                self.driver.close()
            self.driver = None
        return self.driver

    def save(self, graph: dict) -> dict:
        scan_id = graph["scan_id"]
        local_graph = nx.MultiDiGraph(scan_id=scan_id)
        for node in graph["nodes"]:
            local_graph.add_node(node["id"], kind=node["kind"], scan_id=scan_id, **node["properties"])
        for edge in graph["edges"]:
            local_graph.add_edge(edge["source"], edge["target"], key=edge["id"], type=edge["type"], scan_id=scan_id, **edge["properties"])
        backend = "networkx"
        driver = self._driver()
        if driver:
            try:
                with driver.session() as session:
                    for kind in sorted(NODE_KINDS):
                        records = [{"id": node["id"], "scan_id": scan_id, **node["properties"]} for node in graph["nodes"] if node["kind"] == kind]
                        if records:
                            session.run(f"UNWIND $rows AS row MERGE (n:PrivacyLintNode:{kind} {{id: row.id, scan_id: row.scan_id}}) SET n += row", rows=records).consume()
                    for relationship in ("FLOWS_TO", "HAS_FINDING"):
                        records = [{"id": edge["id"], "scan_id": scan_id, "source": edge["source"], "target": edge["target"], "type": edge["type"], **edge["properties"]} for edge in graph["edges"] if edge["type"] == relationship]
                        if records:
                            session.run(f"""UNWIND $rows AS row
                                MATCH (a:PrivacyLintNode {{id: row.source, scan_id: row.scan_id}})
                                MATCH (b:PrivacyLintNode {{id: row.target, scan_id: row.scan_id}})
                                MERGE (a)-[r:{relationship} {{id: row.id, scan_id: row.scan_id}}]->(b)
                                SET r += row""", rows=records).consume()
                backend = "neo4j"
            except Exception:
                backend = "networkx"
        graph["backend"] = backend
        self.graphs[scan_id] = graph
        self.networkx[scan_id] = local_graph
        return graph

    def get(self, scan_id: str) -> dict | None:
        return self.graphs.get(scan_id)

    def close(self) -> None:
        if self.driver:
            self.driver.close()


def to_graphml(graph: nx.MultiDiGraph) -> str:
    return "\n".join(nx.generate_graphml(graph, encoding="utf-8"))


def to_svg(graph: dict) -> str:
    nodes = graph["nodes"]
    width = 920
    row_height = 86
    height = max(180, 80 + len(nodes) * row_height)
    positions = {node["id"]: (100 + (index % 4) * 210, 55 + (index // 4) * row_height) for index, node in enumerate(nodes)}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">', '<rect width="100%" height="100%" fill="#0b0f14"/>', '<g stroke="#334155" stroke-width="2">']
    for edge in graph["edges"]:
        x1, y1 = positions[edge["source"]]
        x2, y2 = positions[edge["target"]]
        parts.append(f'<path d="M{x1 + 72},{y1 + 20} C{x1 + 130},{y1 + 20} {x2 - 40},{y2 + 20} {x2},{y2 + 20}" fill="none" marker-end="url(#arrow)"/>')
    parts.extend(['</g>', '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#64748b"/></marker></defs>'])
    for node in nodes:
        x, y = positions[node["id"]]
        kind = node["kind"]
        label = html.escape(str(node["properties"].get("label", kind))[:28])
        sub = html.escape(str(node["properties"].get("file", node["properties"].get("category", "")))[:34])
        color = COLORS.get(kind, "#64748b")
        parts.append(f'<g><rect x="{x}" y="{y}" width="150" height="46" rx="9" fill="#121821" stroke="{color}" stroke-width="1.5"/><text x="{x + 9}" y="{y + 18}" fill="{color}" font-family="Arial,sans-serif" font-size="10">{kind}</text><text x="{x + 9}" y="{y + 34}" fill="#e5e7eb" font-family="Arial,sans-serif" font-size="11">{label}</text><title>{sub}</title></g>')
    parts.append('</svg>')
    return "".join(parts)


def to_png(graph: dict) -> bytes:
    nodes = graph["nodes"]
    width, row_height = 920, 86
    height = max(180, 80 + len(nodes) * row_height)
    positions = {node["id"]: (100 + (index % 4) * 210, 55 + (index // 4) * row_height) for index, node in enumerate(nodes)}
    image = Image.new("RGB", (width, height), "#0b0f14")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    for edge in graph["edges"]:
        x1, y1 = positions[edge["source"]]
        x2, y2 = positions[edge["target"]]
        draw.line((x1 + 150, y1 + 22, x2, y2 + 22), fill="#334155", width=2)
    for node in nodes:
        x, y = positions[node["id"]]
        kind = node["kind"]
        color = COLORS.get(kind, "#64748b")
        draw.rounded_rectangle((x, y, x + 150, y + 46), radius=8, fill="#121821", outline=color, width=2)
        draw.text((x + 8, y + 5), kind, fill=color, font=font)
        label = str(node["properties"].get("label", kind))[:22]
        draw.text((x + 8, y + 24), label, fill="#e5e7eb", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()
