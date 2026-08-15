/*
  The shared fixtures every frame state draws from. Loaded by nothing on its own — each
  state file below copies what it needs, so a state reads as the exact answer set the box
  would have given, and a change to one frame cannot silently change another.

  Kept here as a reference for the literal key spellings, which differ by route on purpose:
  /me and /capabilities are camelCase, the report objects from /mine are snake_case.

  CAPS = {
    accounts: true, passkeys: true, oauthProviders: ["google", "github"],
    mailConfigured: true, route: "/report",
    limits: {passwordMin: 8, passwordMax: 200, titleMax: 200, detailMax: 8000,
             reproMax: 2000, passkeysPerAccount: 10, maxAccounts: 10000, maxProjects: 100}
  }

  ME = {
    id: "acct-4f1c9a8e2b7d40518c63aa5f0e19d2b7", email: "rocky@rockywearsahat.com",
    emailVerified: true, plan: "free", hasPassword: true,
    oauthProviders: ["github"],
    passkeys: [{id: "pk_9f2a…", label: "this Mac", createdUnix: 1786400000}],
    createdUnix: 1785600000
  }
*/
