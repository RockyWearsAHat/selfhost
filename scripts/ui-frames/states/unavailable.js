/* A box where the operator never turned accounts on. */
window.__STATE = {
  "routes": {
    "GET /capabilities": {
      "status": 404,
      "body": {
        "error": "no such endpoint"
      }
    },
    "GET /me": {
      "status": 404,
      "body": {
        "error": "no such endpoint"
      }
    }
  }
};
