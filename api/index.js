const BASE_URL = "https://gconectn10.vercel.app";
const FACEBOOK_API = "https://graph.facebook.com/v26.0";

/*
 * =========================================================
 * Helpers
 * =========================================================
 */

function json(res, status, data) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.end(JSON.stringify(data));
}

function getPath(req) {
  try {
    const host = req.headers?.host || "gconectn10.vercel.app";
    const url = new URL(req.url || "/", `https://${host}`);
    return {
      path: url.pathname,
      searchParams: url.searchParams
    };
  } catch (error) {
    return {
      path: "/",
      searchParams: new URLSearchParams()
    };
  }
}

async function readBody(req) {
  // Vercel may already parse JSON body
  if (req.body && typeof req.body === "object") {
    return req.body;
  }

  let raw = "";

  try {
    for await (const chunk of req) {
      raw += chunk.toString();
    }
  } catch (error) {
    return {};
  }

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    // Support application/x-www-form-urlencoded
    try {
      const params = new URLSearchParams(raw);
      return Object.fromEntries(params.entries());
    } catch {
      return {};
    }
  }
}

/*
 * =========================================================
 * Facebook OAuth code exchange
 * =========================================================
 */

async function exchangeFacebookCode(code, res, redirectUriOverride) {
  const appId = process.env.FB_APP_ID;
  const appSecret = process.env.FB_APP_SECRET;

  if (!appId || !appSecret) {
    console.error("Missing Facebook environment variables");

    return json(res, 500, {
      status: "error",
      message: "Facebook environment variables are missing"
    });
  }

  const redirectUri =
    redirectUriOverride ||
    process.env.FB_REDIRECT_URI ||
    `${BASE_URL}/auth/facebook/callback`;

  try {
    /*
     * -------------------------------------------------------
     * 1. Exchange Facebook authorization code
     * -------------------------------------------------------
     */

    const tokenUrl = new URL(
      `${FACEBOOK_API}/oauth/access_token`
    );

    tokenUrl.searchParams.set("client_id", appId);
    tokenUrl.searchParams.set("client_secret", appSecret);
    tokenUrl.searchParams.set("redirect_uri", redirectUri);
    tokenUrl.searchParams.set("code", code);

    const tokenResponse = await fetch(tokenUrl.toString());

    const tokenText = await tokenResponse.text();

    let tokenData;

    try {
      tokenData = JSON.parse(tokenText);
    } catch {
      tokenData = {};
    }

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("FACEBOOK TOKEN ERROR:", tokenData);

      return json(res, 400, {
        status: "error",
        message: "Invalid Facebook authorization code"
      });
    }

    /*
     * -------------------------------------------------------
     * 2. Get Facebook user information
     * -------------------------------------------------------
     */

    const userUrl = new URL(`${FACEBOOK_API}/me`);

    userUrl.searchParams.set(
      "fields",
      "id,name,email"
    );

    userUrl.searchParams.set(
      "access_token",
      tokenData.access_token
    );

    const userResponse = await fetch(userUrl.toString());

    const userText = await userResponse.text();

    let userData;

    try {
      userData = JSON.parse(userText);
    } catch {
      userData = {};
    }

    if (!userResponse.ok || !userData.id) {
      console.error("FACEBOOK USER ERROR:", userData);

      return json(res, 400, {
        status: "error",
        message: "Could not obtain Facebook user information"
      });
    }

    /*
     * -------------------------------------------------------
     * 3. Return our application's result
     * -------------------------------------------------------
     *
     * Do NOT return the Facebook access token to the client.
     */

    return json(res, 200, {
      status: "success",
      user: userData
    });

  } catch (error) {
    console.error(
      "FACEBOOK EXCHANGE ERROR:",
      error?.message || error
    );

    return json(res, 500, {
      status: "error",
      message: "Facebook authentication failed"
    });
  }
}

/*
 * =========================================================
 * Main Vercel Function
 * =========================================================
 */

module.exports = async (req, res) => {
  try {
    const { path, searchParams } = getPath(req);

    /*
     * =====================================================
     * OPTIONS / CORS
     * =====================================================
     */

    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,OPTIONS"
      );
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
      );

      return res.status(204).end();
    }

    /*
     * =====================================================
     * HOME
     * =====================================================
     */

    if (
      path === "/" ||
      path === "/api" ||
      path === "/api/"
    ) {
      return json(res, 200, {
        status: 0,
        client_log: false
      });
    }

    /*
     * =====================================================
     * HEALTH
     * =====================================================
     */

    if (path === "/health") {
      return json(res, 200, {
        status: "ok"
      });
    }

    /*
     * =====================================================
     * APP INFO
     * =====================================================
     */

    if (path === "/app/info/get") {
      return json(res, 200, {
        status: 0,
        client_log: false
      });
    }

    /*
     * =====================================================
     * APP FEEDBACK
     * =====================================================
     */

    if (path === "/app/feedback") {
      return json(res, 200, {
        status: 0,
        supports_implicit_sdk_logging: true,
        gdpv4_nux_enabled: false,
        gdpv4_nux_content: {},
        android_dialog_configs: {},
        android_sdk_error_categories: [],
        ios_dialog_configs: {},
        ios_sdk_dialog_flows: {},
        ios_sdk_error_categories: [],
        id: "feedback"
      });
    }

    /*
     * =====================================================
     * CONNECT
     * =====================================================
     */

    if (path === "/connect") {
      return json(res, 200, {
        status: "ok",
        path: "/connect"
      });
    }

    /*
     * =====================================================
     * FACEBOOK LOGIN
     * =====================================================
     */

    if (path === "/auth/facebook") {
      if (req.method !== "GET") {
        return json(res, 405, {
          status: "error",
          message: "Method Not Allowed"
        });
      }

      const appId = process.env.FB_APP_ID;

      if (!appId) {
        return json(res, 500, {
          status: "error",
          message: "FB_APP_ID is not configured"
        });
      }

      const redirectUri =
        process.env.FB_REDIRECT_URI ||
        `${BASE_URL}/auth/facebook/callback`;

      const params = new URLSearchParams();

      params.set("client_id", appId);
      params.set("redirect_uri", redirectUri);
      params.set("scope", "email,public_profile");
      params.set("response_type", "code");

      return res.redirect(
        `https://www.facebook.com/v26.0/dialog/oauth?${params.toString()}`
      );
    }

    /*
     * =====================================================
     * FACEBOOK CALLBACK
     * =====================================================
     */

    if (path === "/auth/facebook/callback") {
      if (req.method !== "GET") {
        return json(res, 405, {
          status: "error",
          message: "Method Not Allowed"
        });
      }

      const error = searchParams.get("error");
      const errorDescription =
        searchParams.get("error_description");

      if (error) {
        return json(res, 400, {
          status: "error",
          message: "Facebook OAuth error",
          error: error,
          description: errorDescription || null
        });
      }

      const code = searchParams.get("code");

      if (!code) {
        return json(res, 400, {
          status: "error",
          message: "No Facebook authorization code"
        });
      }

      return exchangeFacebookCode(code, res);
    }

    /*
     * =====================================================
     * OUR FACEBOOK EXCHANGE ENDPOINT
     * =====================================================
     *
     * POST:
     *
     * /oauth/token/facebook/exchange
     *
     * Body:
     * {
     *   "code": "FACEBOOK_AUTHORIZATION_CODE"
     * }
     *
     * Also accepts:
     *
     * /api/oauth/token/facebook/exchange
     *
     * =====================================================
     */

    if (
      path === "/oauth/token/facebook/exchange" ||
      path === "/api/oauth/token/facebook/exchange"
    ) {
      if (req.method !== "POST") {
        return json(res, 405, {
          status: "error",
          message: "Method Not Allowed"
        });
      }

      const body = await readBody(req);

      const code =
        body?.code ||
        body?.authorization_code ||
        body?.auth_code;

      if (!code) {
        return json(res, 400, {
          error: "invalid_grant",
          code: 2017
        });
      }

      return exchangeFacebookCode(code, res);
    }

    /*
     * =====================================================
     * OUR ALTERNATIVE FACEBOOK EXCHANGE
     * =====================================================
     */

    if (
      path === "/auth/facebook/exchange" ||
      path === "/api/auth/facebook/exchange"
    ) {
      if (req.method !== "POST") {
        return json(res, 405, {
          status: "error",
          message: "Method Not Allowed"
        });
      }

      const body = await readBody(req);

      const code =
        body?.code ||
        body?.authorization_code ||
        body?.auth_code;

      if (!code) {
        return json(res, 400, {
          status: "error",
          message: "Facebook authorization code is required"
        });
      }

      return exchangeFacebookCode(code, res);
    }

    /*
     * =====================================================
     * 404
     * =====================================================
     */

    return json(res, 404, {
      status: 404,
      message: "Endpoint not found",
      path: path
    });

  } catch (error) {
    /*
     * Never allow an unexpected exception to crash
     * the whole Vercel function without JSON response.
     */

    console.error(
      "FUNCTION ERROR:",
      error?.stack || error?.message || error
    );

    return json(res, 500, {
      status: "error",
      message: "Internal server error"
    });
  }
};
