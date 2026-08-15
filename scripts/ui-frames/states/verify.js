/* The confirmation link from the verification email, before it is pressed. */
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
    "POST /verify/confirm": {
      "status": 200,
      "body": {
        "verified": true
      }
    }
  }
};
