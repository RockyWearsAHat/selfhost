/* The ledger before anything has been filed. */
window.__STATE = {
  "hash": "#mine",
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
      "status": 200,
      "body": {
        "id": "acct-4f1c9a8e2b7d40518c63aa5f0e19d2b7",
        "email": "rocky@rockywearsahat.com",
        "emailVerified": true,
        "plan": "free",
        "hasPassword": true,
        "oauthProviders": [
          "github"
        ],
        "passkeys": [
          {
            "id": "pk_9f2a7c41d8e0",
            "label": "this Mac",
            "createdUnix": 1786400000
          },
          {
            "id": "pk_2b19ee40aa73",
            "label": "iPhone or iPad",
            "createdUnix": 1786500000
          }
        ],
        "createdUnix": 1785600000
      }
    },
    "GET /projects": {
      "status": 200,
      "body": {
        "projects": [
          "selfhost",
          "dx",
          "reports",
          "console",
          "mail"
        ]
      }
    },
    "GET /mine": {
      "status": 200,
      "body": {
        "reports": []
      }
    },
    "GET /download": {
      "status": 200,
      "body": {
        "downloadUrl": "https://github.com/RockyWearsAHat/selfhost/archive/refs/heads/main.zip",
        "repository": "https://github.com/RockyWearsAHat/selfhost",
        "branch": "main",
        "setup": "Clone the repository (or unzip the downloaded archive), then run `cargo build --release` from its root."
      }
    }
  }
};
