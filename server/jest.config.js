module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/tests/**/*.test.js'],
  // The API boundary never accepts URLs from clients, only target IDs — but the
  // URL guard is defense-in-depth for the scan service, so it gets its own suite.
  testTimeout: 20000,
};
