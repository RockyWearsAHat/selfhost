/* Signed out, and the account door has spent its allowance. */
window.__STATE = {
  "routes": {
    "GET /capabilities": {
      "status": 200,
      "body": {
        "accounts": true,
        "passkeys": true,
        "oauthProviders": [
          "google",
          "github"
        ],
        "mailConfigured": true,
        "route": "/report",
        "limits": {
          "passwordMin": 8,
          "passwordMax": 200,
          "titleMax": 200,
          "detailMax": 8000,
          "reproMax": 2000,
          "passkeysPerAccount": 10,
          "maxAccounts": 10000,
          "maxProjects": 100
        }
      }
    },
    "GET /me": {
      "status": 401,
      "body": {
        "error": "sign in first"
      }
    },
    "POST /login": {
      "status": 429,
      "headers": {
        "Retry-After": "14"
      },
      "body": {
        "error": "too many reports from here just now \u2014 the wait is in Retry-After"
      }
    }
  }
};
