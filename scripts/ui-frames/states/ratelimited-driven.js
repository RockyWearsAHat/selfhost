/* The account door has spent its allowance: a 429 with its Retry-After, under the form. */
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

/* The still-frame harness cannot click, so the state that needs a press drives itself: the
   page's own handlers run, exactly as a reader's click would run them. */
window.addEventListener("load", function () {
  setTimeout(function () {
    var email = document.getElementById("login-email");
    var password = document.getElementById("login-password");
    if (email) email.value = "rocky@rockywearsahat.com";
    if (password) password.value = "correct horse battery staple";
    var form = document.getElementById("login-form");
    if (form) form.dispatchEvent(new Event("submit", {cancelable: true, bubbles: true}));
  }, 80);
});
