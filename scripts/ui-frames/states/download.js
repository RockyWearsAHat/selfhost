/* The download pane, with the archive and the clone line. */
window.__STATE = {
  "hash": "#download",
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
        "reports": [
          {
            "project": "selfhost",
            "id": "report-9c41ab77",
            "kind": "bug",
            "title": "Verification link renders raw JSON in the browser",
            "detail": "Clicked the link in the confirmation mail and landed on a page showing {\"verified\":true} in the browser's default font. Expected a page that says the address is confirmed.",
            "route": "",
            "repro": "Register, open the mail, click the link.",
            "first_at": "2026-08-13T09:15:02Z",
            "last_at": "2026-08-15T18:42:11Z",
            "sightings": 3,
            "delivered": false,
            "account_id": "acct-4f1c9a8e2b7d40518c63aa5f0e19d2b7",
            "seen": [
              {
                "at": "2026-08-13T09:15:02Z",
                "tool": "safari",
                "platform": "macos",
                "workspace": "self-host",
                "source": "web",
                "detail": "first sighting"
              },
              {
                "at": "2026-08-14T21:02:47Z",
                "tool": "chrome",
                "platform": "windows",
                "workspace": "self-host",
                "source": "web",
                "detail": ""
              },
              {
                "at": "2026-08-15T18:42:11Z",
                "tool": "safari",
                "platform": "ios",
                "workspace": "self-host",
                "source": "web",
                "detail": ""
              }
            ]
          },
          {
            "project": "dx",
            "id": "report-3f80d2e1",
            "kind": "suggestion",
            "title": "dx_search should answer with the block that states the fact, not its heading",
            "detail": "A search that lands on a heading costs a second read to get the sentence that actually answers the question.",
            "route": "",
            "repro": "",
            "first_at": "2026-08-14T11:07:00Z",
            "last_at": "2026-08-14T11:07:00Z",
            "sightings": 1,
            "delivered": true,
            "account_id": "acct-4f1c9a8e2b7d40518c63aa5f0e19d2b7",
            "seen": []
          },
          {
            "project": "console",
            "id": "report-71bc4d09",
            "kind": "observation",
            "title": "Local Network permission resets when the .app is reinstalled",
            "detail": "After scripts/macos/macos-app.sh install the console cannot reach the box until the permission prompt is accepted again (Errno 65 until then).",
            "route": "",
            "repro": "",
            "first_at": "2026-08-11T08:12:00Z",
            "last_at": "2026-08-12T16:30:00Z",
            "sightings": 2,
            "delivered": false,
            "account_id": "acct-4f1c9a8e2b7d40518c63aa5f0e19d2b7",
            "seen": []
          }
        ]
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
