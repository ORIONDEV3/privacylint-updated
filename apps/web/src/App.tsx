import { Navigate, Route, Routes } from "react-router-dom";
import AuthLayout from "./components/AuthLayout";
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyOtp from "./pages/VerifyOtp";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Workspace from "./pages/Workspace";
import {
  BadgePage, FindingsPage, FixesPage, InventoryPage, LineagePage, NewScanPage,
  OverviewPage, PrAutomationPage, ReportsPage, RulesPage, ScanDetailPage,
  ScanListPage, SecurityPage, SettingsPage, TestsPage,
} from "./pages/ConsolePages";

export default function App() {
  return <Routes>
    <Route element={<AuthLayout />}>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify" element={<VerifyOtp />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
    </Route>
    <Route path="/workspace" element={<Workspace />}>
      <Route index element={<Navigate to="overview" replace />} />
      <Route path="overview" element={<OverviewPage />} />
      <Route path="scans/new" element={<NewScanPage />} />
      <Route path="scans" element={<ScanListPage />} />
      <Route path="scans/:scanId" element={<ScanDetailPage />} />
      <Route path="findings" element={<FindingsPage />} />
      <Route path="lineage" element={<LineagePage />} />
      <Route path="graph/:scanId" element={<LineagePage />} />
      <Route path="inventory/:scanId" element={<InventoryPage />} />
      <Route path="fixes" element={<FixesPage />} />
      <Route path="tests" element={<TestsPage />} />
      <Route path="reports" element={<ReportsPage />} />
      <Route path="pr" element={<PrAutomationPage />} />
      <Route path="badge" element={<BadgePage />} />
      <Route path="security" element={<SecurityPage />} />
      <Route path="rules" element={<RulesPage />} />
      <Route path="settings" element={<SettingsPage />} />
    </Route>
    <Route path="/" element={<Navigate to="/login" replace />} />
    <Route path="*" element={<Navigate to="/login" replace />} />
  </Routes>;
}

