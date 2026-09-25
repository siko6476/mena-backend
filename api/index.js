const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

const BASE_URL =
  process.env.BASE_URL ||
  "https://gconectn10.vercel.app";

const FB_APP_ID = process.env.FB_APP_ID;
const FB_APP_SECRET = process.env.FB_APP_SECRET;

const FB_REDIRECT_URI =
  process.env.FB_REDIRECT_URI ||
  `${BASE_URL}/auth/facebook/callback`;

const SESSION_SECRET = process.env.SESSION_SECRET;

const FB_API_VERSION = "v26.0";

const SESSION_SECONDS = 7 * 24 * 60 * 60;


// --------------------------------------------------
// Helpers
// --------------------------------------------------

function json(res, status, data) {
  return res.status(status).json(data);
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(value) {
  return Buffer.from(
    value
      .replace(/-/g, "+")
      .replace(/_/g, "/"),
    "base64"
  ).toString("utf8");
}

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64url");
}


// --------------------------------------------------
// Session
// --------------------------------------------------

function createSession(user) {
  if (!SESSION_SECRET) {
    throw new Error("SESSION_SECRET is not configured");
  }

  const payload = {
    sub: String(user.id),
    name: user.name || null,
    email: user.email || null,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  };

  const encoded = base64url(JSON.stringify(payload));
  const signature = sign(encoded);

  return `${encoded}.${signature}`;
}


function verifySession(token) {
  try {
    if (!SESSION_SECRET || !token) {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const [encoded, signature] = parts;

    const expected = sign(encoded);

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return null;
    }

    const payload = JSON.parse(
      fromBase64url(encoded)
    );

    const now = Math.floor(Date.now() / 1000);

    if (!payload.exp || payload.exp < now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}


// --------------------------------------------------
// OAuth state
// --------------------------------------------------

function createState() {
  if (!SESSION_SECRET) {
    throw new Error("SESSION_SECRET is not configured");
  }

  const payload = {
    nonce: crypto.randomBytes(24).toString("hex"),
    iat: Math.floor(Date.now() / 1000)
  };

  const encoded = base64url(
    JSON.stringify(payload)
  );

  return `${encoded}.${sign(encoded)}`;
}


function verifyState(state) {
  try {
    if (!SESSION_SECRET || !state) {
      return false;
    }

    const parts = state.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const [encoded, signature] = parts;

    const expected = sign(encoded);

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return false;
    }

    const payload = JSON.parse(
      fromBase64url(encoded)
    );

    const now = Math.floor(Date.now() / 1000);

    // State valid for 10 minutes
    if (
      !payload.iat ||
      now - payload.iat > 600
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}


// --------------------------------------------------
// Basic routes
// --------------------------------------------------

app.get("/", (req, res) => {
  return json(res, 200, {
    status: "ok",
    service: "N10 OAuth API"
  });
});


app.get("/health", (req, res) => {
  return json(res, 200, {
    status: "ok"
  });
});


app.get("/app/info/get", (req, res) => {
  return json(res, 200, {
    status: 0,
    client_log: false
  });
});


app.get("/connect", (req, res) => {
  return json(res, 200, {
    status: "ok",
    path: "/connect"
  });
});


// --------------------------------------------------
// Start Facebook OAuth
// --------------------------------------------------

app.get("/auth/facebook", (req, res) => {
  try {
    if (!FB_APP_ID) {
      return json(res, 500, {
        status: "error",
        message: "FB_APP_ID is not configured"
      });
    }

    if (!SESSION_SECRET) {
      return json(res, 500, {
        status: "error",
        message: "SESSION_SECRET is not configured"
      });
    }

    const state = createState();

    const params = new URLSearchParams({
      client_id: FB_APP_ID,
      redirect_uri: FB_REDIRECT_URI,
      scope: "email,public_profile",
      response_type: "code",
      state
    });

    const url =
      `https://www.facebook.com/${FB_API_VERSION}/dialog/oauth?` +
      params.toString();

    return res.redirect(307, url);
  } catch (error) {
    console.error(error);

    return json(res, 500, {
      status: "error",
      message: "Unable to start Facebook OAuth"
    });
  }
});


// --------------------------------------------------
// Facebook OAuth callback
// --------------------------------------------------

app.get("/auth/facebook/callback", async (req, res) => {
  try {
    const {
      code,
      state,
      error,
      error_description
    } = req.query;

    if (error) {
      return json(res, 400, {
        status: "error",
        message: error_description || error
      });
    }

    if (!code) {
      return json(res, 400, {
        status: "error",
        message: "No Facebook authorization code"
      });
    }

    if (!state || !verifyState(state)) {
      return json(res, 400, {
        status: "error",
        message: "Invalid or expired OAuth state"
      });
    }

    if (!FB_APP_ID || !FB_APP_SECRET) {
      return json(res, 500, {
        status: "error",
        message: "Facebook OAuth credentials are not configured"
      });
    }

    // Exchange Facebook authorization code
    const tokenParams = new URLSearchParams({
      client_id: FB_APP_ID,
      client_secret: FB_APP_SECRET,
      redirect_uri: FB_REDIRECT_URI,
      code: String(code)
    });

    const tokenResponse = await fetch(
      `https://graph.facebook.com/${FB_API_VERSION}/oauth/access_token`,
      {
        method: "POST",
        headers: {
          "content-type":
            "application/x-www-form-urlencoded"
        },
        body: tokenParams.toString()
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error(
        "Facebook token exchange failed:",
        tokenData
      );

      return json(res, 400, {
        status: "error",
        message: "Facebook authorization code exchange failed"
      });
    }

    // Get Facebook user
    const userParams = new URLSearchParams({
      fields: "id,name,email",
      access_token: tokenData.access_token
    });

    const userResponse = await fetch(
      `https://graph.facebook.com/${FB_API_VERSION}/me?${userParams.toString()}`
    );

    const userData = await userResponse.json();

    if (!userResponse.ok || !userData.id) {
      console.error(
        "Facebook user request failed:",
        userData
      );

      return json(res, 400, {
        status: "error",
        message: "Unable to retrieve Facebook user"
      });
    }

    const user = {
      id: userData.id,
      name: userData.name || null,
      email: userData.email || null
    };

    const session = createSession(user);

    return json(res, 200, {
      status: "success",

      user,

      session: {
        token: session,
        expires_in: SESSION_SECONDS
      }
    });
  } catch (error) {
    console.error(
      "Facebook callback error:",
      error
    );

    return json(res, 500, {
      status: "error",
      message: "Facebook OAuth callback failed"
    });
  }
});


// --------------------------------------------------
// NEW ENDPOINT
// POST /oauth/token/facebook/exchange
// --------------------------------------------------

app.post(
  "/oauth/token/facebook/exchange",
  async (req, res) => {
    try {
      if (!FB_APP_ID || !FB_APP_SECRET) {
        return json(res, 500, {
          error: "server_configuration_error"
        });
      }

      if (!SESSION_SECRET) {
        return json(res, 500, {
          error: "server_configuration_error"
        });
      }

      /*
       * Supported request:
       *
       * JSON:
       * {
       *   "code": "FACEBOOK_AUTHORIZATION_CODE"
       * }
       *
       * or form-urlencoded:
       *
       * code=FACEBOOK_AUTHORIZATION_CODE
       */

      const code =
        req.body?.code ||
        req.body?.authorization_code ||
        req.body?.fb_code;

      if (!code) {
        return json(res, 400, {
          error: "invalid_grant",
          code: 2017,
          message: "Facebook authorization code is required"
        });
      }

      // Use our configured redirect URI.
      const redirectUri =
        req.body?.redirect_uri ||
        FB_REDIRECT_URI;

      const tokenParams = new URLSearchParams({
        client_id: FB_APP_ID,
        client_secret: FB_APP_SECRET,
        redirect_uri: redirectUri,
        code: String(code)
      });

      const facebookResponse = await fetch(
        `https://graph.facebook.com/${FB_API_VERSION}/oauth/access_token`,
        {
          method: "POST",

          headers: {
            "content-type":
              "application/x-www-form-urlencoded"
          },

          body: tokenParams.toString()
        }
      );

      const facebookToken =
        await facebookResponse.json();

      if (
        !facebookResponse.ok ||
        !facebookToken.access_token
      ) {
        console.error(
          "Facebook exchange error:",
          facebookToken
        );

        return json(res, 400, {
          error: "invalid_grant",
          code: 2017,
          message: "Invalid or expired Facebook authorization code"
        });
      }

      // Retrieve Facebook user
      const userParams = new URLSearchParams({
        fields: "id,name,email",
        access_token: facebookToken.access_token
      });

      const userResponse = await fetch(
        `https://graph.facebook.com/${FB_API_VERSION}/me?${userParams.toString()}`
      );

      const userData = await userResponse.json();

      if (
        !userResponse.ok ||
        !userData.id
      ) {
        console.error(
          "Facebook user error:",
          userData
        );

        return json(res, 400, {
          error: "invalid_grant",
          code: 2017,
          message: "Unable to retrieve Facebook user"
        });
      }

      const user = {
        id: userData.id,
        name: userData.name || null,
        email: userData.email || null
      };

      const sessionToken =
        createSession(user);

      return json(res, 200, {
        status: "success",

        user,

        access_token: sessionToken,

        token_type: "Bearer",

        expires_in: SESSION_SECONDS
      });
    } catch (error) {
      console.error(
        "Facebook exchange endpoint error:",
        error
      );

      return json(res, 500, {
        error: "server_error",
        message: "Facebook exchange failed"
      });
    }
  }
);


// --------------------------------------------------
// Check session
// --------------------------------------------------

app.get("/auth/session", (req, res) => {
  try {
    const auth =
      req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return json(res, 401, {
        status: "error",
        message: "Authorization required"
      });
    }

    const token =
      auth.slice("Bearer ".length).trim();

    const session =
      verifySession(token);

    if (!session) {
      return json(res, 401, {
        status: "error",
        message: "Invalid or expired session"
      });
    }

    return json(res, 200, {
      status: "success",

      user: {
        id: session.sub,
        name: session.name,
        email: session.email
      },

      expires_at: session.exp
    });
  } catch {
    return json(res, 500, {
      status: "error",
      message: "Session check failed"
    });
  }
});


// --------------------------------------------------
// 404
// --------------------------------------------------

app.use((req, res) => {
  return json(res, 404, {
    status: 404,
    message: "Endpoint not found"
  });
});


// --------------------------------------------------
// Export for Vercel
// --------------------------------------------------

module.exports = app;
