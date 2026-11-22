module.exports = {
  testEnvironment: "node",
  testMatch: ["**/test/**/*.test.js"],
  transform: {},
  collectCoverageFrom: ["src/**/*.js", "!src/server.js", "!src/db.js", "!src/email.js"]
};

