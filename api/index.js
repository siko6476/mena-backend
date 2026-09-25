const BASE_URL = "https://gconectn10.vercel.app";
const FACEBOOK_API = "https://graph.facebook.com/v26.0";

/*
 * =========================================================
 * Helpers
 * =========================================================
 */

function json(res, status, data) {
  res.status(status);
  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  return res.end(
    JSON.stringify(data)
  );
}

function getPath(req) {
  try {
    const host =
      req.headers?.host ||
      "gconectn10.vercel.app";

    const url = new URL(
      req.url || "/",
      `https://${host}`
    );

    return {
      path: url.pathname,
      searchParams: url.searchParams
    };
  } catch {
    return {
      path: "/",
      searchParams:
        new URLSearchParams()
    };
  }
}

async function readBody(req) {
  if (
    req.body &&
    typeof req.body === "object"
  ) {
    return req.body;
  }

  let raw = "";

  try {
    for await (const chunk of req) {
      raw += chunk.toString();
    }
  } catch {
    return {};
  }

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    try {
      const params =
        new URLSearchParams(raw);

      return Object.fromEntries(
        params.entries()
      );
    } catch {
      return {};
    }
  }
}

/*
 * =========================================================
 * Facebook Authorization Code Exchange
 * =========================================================
 */

async function exchangeFacebookCode(
  code,
  res,
  redirectUriOverride
) {
  const appId =
    process.env.FB_APP_ID;

  const appSecret =
    process.env.FB_APP_SECRET;

  if (!appId || !appSecret) {
    console.error(
      "Missing Facebook environment variables"
    );

    return json(res, 500, {
      status: "error",
      message:
        "Facebook environment variables are missing"
    });
  }

  const redirectUri =
    redirectUriOverride ||
    process.env.FB_REDIRECT_URI ||
    `${BASE_URL}/auth/facebook/callback`;

  try {
    /*
     * =====================================================
     * Exchange authorization code
     * =====================================================
     */

    const tokenUrl =
      new URL(
        `${FACEBOOK_API}/oauth/access_token`
      );

    tokenUrl.searchParams.set(
      "client_id",
      appId
    );

    tokenUrl.searchParams.set(
      "client_secret",
      appSecret
    );

    tokenUrl.searchParams.set(
      "redirect_uri",
      redirectUri
    );

    tokenUrl.searchParams.set(
      "code",
      code
    );

    const tokenResponse =
      await fetch(
        tokenUrl.toString()
      );

    const tokenText =
      await tokenResponse.text();

    let tokenData = {};

    try {
      tokenData =
        JSON.parse(tokenText);
    } catch {
      tokenData = {};
    }

    if (
      !tokenResponse.ok ||
      !tokenData.access_token
    ) {
      console.error(
        "FACEBOOK TOKEN ERROR:",
        {
          status:
            tokenResponse.status,

          error:
            tokenData?.error ||
            null,

          error_type:
            tokenData?.error?.type ||
            null,

          error_code:
            tokenData?.error?.code ||
            null
        }
      );

      return json(res, 400, {
        status: "error",
        message:
          "Invalid Facebook authorization code"
      });
    }

    /*
     * Get Facebook user
     */

    return getFacebookUser(
      tokenData.access_token,
      res
    );

  } catch (error) {
    console.error(
      "FACEBOOK CODE EXCHANGE ERROR:",
      error?.message ||
      error
    );

    return json(res, 500, {
      status: "error",
      message:
        "Facebook authentication failed"
    });
  }
}

/*
 * =========================================================
 * Facebook Access Token Validation
 * =========================================================
 *
 * This is used when the application sends:
 *
 * client_id
 * client_secret
 * facebook_access_token
 *
 * The client_secret value is NEVER trusted.
 *
 * The real FB_APP_SECRET comes from Vercel.
 * =========================================================
 */

async function exchangeFacebookAccessToken(
  facebookAccessToken,
  clientId,
  res
) {
  const appId =
    process.env.FB_APP_ID;

  const appSecret =
    process.env.FB_APP_SECRET;

  if (!appId || !appSecret) {
    console.error(
      "Missing Facebook environment variables"
    );

    return json(res, 500, {
      status: "error",
      message:
        "Facebook environment variables are missing"
    });
  }

  /*
   * =====================================================
   * Verify client_id
   * =====================================================
   */

  if (
    !clientId ||
    String(clientId) !==
      String(appId)
  ) {
    return json(res, 401, {
      error:
        "invalid_client",
      message:
        "Invalid Facebook client_id"
    });
  }

  try {
    /*
     * ===================================================
     * Debug Facebook access token
     * ===================================================
     *
     * IMPORTANT:
     * The App Secret stays on the server.
     */

    const debugUrl =
      new URL(
        `${FACEBOOK_API}/debug_token`
      );

    debugUrl.searchParams.set(
      "input_token",
      facebookAccessToken
    );

    const appAccessToken =
      `${appId}|${appSecret}`;

    debugUrl.searchParams.set(
      "access_token",
      appAccessToken
    );

    const debugResponse =
      await fetch(
        debugUrl.toString()
      );

    const debugText =
      await debugResponse.text();

    let debugData = {};

    try {
      debugData =
        JSON.parse(debugText);
    } catch {
      debugData = {};
    }

    /*
     * Invalid token
     */

    if (
      !debugResponse.ok ||
      !debugData?.data?.is_valid
    ) {
      console.error(
        "FACEBOOK TOKEN VALIDATION FAILED:",
        {
          status:
            debugResponse.status,

          error:
            debugData?.error ||
            null
        }
      );

      return json(res, 401, {
        error:
          "invalid_token",
        message:
          "Facebook access token is invalid"
      });
    }

    /*
     * ===================================================
     * Make sure token belongs to our Facebook App
     * ===================================================
     */

    const tokenAppId =
      debugData?.data?.app_id;

    if (
      String(tokenAppId) !==
      String(appId)
    ) {
      return json(res, 401, {
        error:
          "invalid_token",
        message:
          "Facebook access token belongs to another app"
      });
    }

    /*
     * ===================================================
     * Get Facebook user
     * ===================================================
     */

    return getFacebookUser(
      facebookAccessToken,
      res
    );

  } catch (error) {
    console.error(
      "FACEBOOK ACCESS TOKEN ERROR:",
      error?.message ||
      error
    );

    return json(res, 500, {
      status: "error",
      message:
        "Facebook authentication failed"
    });
  }
}

/*
 * =========================================================
 * Get Facebook User
 * =========================================================
 */

async function getFacebookUser(
  accessToken,
  res
) {
  try {
    const userUrl =
      new URL(
        `${FACEBOOK_API}/me`
      );

    userUrl.searchParams.set(
      "fields",
      "id,name,email"
    );

    userUrl.searchParams.set(
      "access_token",
      accessToken
    );

    const userResponse =
      await fetch(
        userUrl.toString()
      );

    const userText =
      await userResponse.text();

    let userData = {};

    try {
      userData =
        JSON.parse(userText);
    } catch {
      userData = {};
    }

    if (
      !userResponse.ok ||
      !userData?.id
    ) {
      console.error(
        "FACEBOOK USER ERROR:",
        {
          status:
            userResponse.status,

          error:
            userData?.error ||
            null
        }
      );

      return json(res, 401, {
        error:
          "invalid_token",
        message:
          "Could not obtain Facebook user information"
      });
    }

    /*
     * ===================================================
     * Success
     * ===================================================
     */

    return json(res, 200, {
      status: "success",
      user: userData
    });

  } catch (error) {
    console.error(
      "FACEBOOK USER REQUEST ERROR:",
      error?.message ||
      error
    );

    return json(res, 500, {
      status: "error",
      message:
        "Could not obtain Facebook user information"
    });
  }
}

/*
 * =========================================================
 * Main Vercel Function
 * =========================================================
 */

module.exports = async (
  req,
  res
) => {
  try {
    const {
      path,
      searchParams
    } = getPath(req);

    const method =
      req.method || "GET";

    /*
     * =====================================================
     * OPTIONS / CORS
     * =====================================================
     */

    if (method === "OPTIONS") {
      res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
      );

      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,OPTIONS"
      );

      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
      );

      return res
        .status(204)
        .end();
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

    if (
      path === "/health"
    ) {
      return json(res, 200, {
        status: "ok"
      });
    }

    /*
     * =====================================================
     * APP INFO
     * =====================================================
     */

    if (
      path === "/app/info/get"
    ) {
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

    if (
      path === "/app/feedback"
    ) {
      return json(res, 200, {
        status: 0,

        supports_implicit_sdk_logging:
          true,

        gdpv4_nux_enabled:
          false,

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

    if (
      path === "/connect"
    ) {
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

    if (
      path === "/auth/facebook"
    ) {
      if (method !== "GET") {
        return json(res, 405, {
          status: "error",
          message:
            "Method Not Allowed"
        });
      }

      const appId =
        process.env.FB_APP_ID;

      if (!appId) {
        return json(res, 500, {
          status: "error",
          message:
            "FB_APP_ID is not configured"
        });
      }

      const redirectUri =
        process.env.FB_REDIRECT_URI ||
        `${BASE_URL}/auth/facebook/callback`;

      const params =
        new URLSearchParams();

      params.set(
        "client_id",
        appId
      );

      params.set(
        "redirect_uri",
        redirectUri
      );

      params.set(
        "scope",
        "email,public_profile"
      );

      params.set(
        "response_type",
        "code"
      );

      return res.redirect(
        `https://www.facebook.com/v26.0/dialog/oauth?${params.toString()}`
      );
    }

    /*
     * =====================================================
     * FACEBOOK CALLBACK
     * =====================================================
     */

    if (
      path ===
      "/auth/facebook/callback"
    ) {
      if (method !== "GET") {
        return json(res, 405, {
          status: "error",
          message:
            "Method Not Allowed"
        });
      }

      const error =
        searchParams.get(
          "error"
        );

      const errorDescription =
        searchParams.get(
          "error_description"
        );

      if (error) {
        return json(res, 400, {
          status: "error",
          message:
            "Facebook OAuth error",

          error:
            error,

          description:
            errorDescription ||
            null
        });
      }

      const code =
        searchParams.get(
          "code"
        );

      if (!code) {
        return json(res, 400, {
          status: "error",
          message:
            "No Facebook authorization code"
        });
      }

      return exchangeFacebookCode(
        code,
        res
      );
    }

    /*
     * =====================================================
     * FACEBOOK TOKEN
     * =====================================================
     *
     * POST:
     * /oauth/token/facebook
     *
     * Supports:
     *
     * 1. code
     * 2. authorization_code
     * 3. auth_code
     * 4. facebook_access_token
     *
     * client_secret sent by the client is ignored.
     * The real secret remains in Vercel.
     * =====================================================
     */

    if (
      path ===
      "/oauth/token/facebook"
    ) {
      if (method !== "POST") {
        return json(res, 405, {
          status: "error",
          message:
            "Method Not Allowed"
        });
      }

      const body =
        await readBody(req);

      const receivedFields =
        body &&
        typeof body === "object"
          ? Object.keys(body)
          : [];

      console.log(
        "FACEBOOK TOKEN REQUEST:",
        {
          method,
          path,
          received_fields:
            receivedFields
        }
      );

      /*
       * Authorization code
       */

      const code =
        body?.code ||
        body?.authorization_code ||
        body?.auth_code;

      if (code) {
        return exchangeFacebookCode(
          code,
          res
        );
      }

      /*
       * Facebook access token
       */

      const facebookAccessToken =
        body?.facebook_access_token;

      const clientId =
        body?.client_id;

      if (
        facebookAccessToken
      ) {
        return exchangeFacebookAccessToken(
          facebookAccessToken,
          clientId,
          res
        );
      }

      /*
       * No supported credential
       */

      return json(res, 400, {
        error:
          "invalid_grant",

        code:
          2017,

        received_fields:
          receivedFields
      });
    }

    /*
     * =====================================================
     * FACEBOOK TOKEN EXCHANGE
     * =====================================================
     *
     * POST:
     * /oauth/token/facebook/exchange
     *
     * POST:
     * /api/oauth/token/facebook/exchange
     *
     * Supports:
     *
     * - client_id
     * - facebook_access_token
     *
     * client_secret from the client is ignored.
     * =====================================================
     */

    if (
      path ===
        "/oauth/token/facebook/exchange" ||
      path ===
        "/api/oauth/token/facebook/exchange"
    ) {
      if (method !== "POST") {
        return json(res, 405, {
          status: "error",
          message:
            "Method Not Allowed"
        });
      }

      const body =
        await readBody(req);

      const receivedFields =
        body &&
        typeof body === "object"
          ? Object.keys(body)
          : [];

      /*
       * SAFE DEBUG LOG
       *
       * Only field names are logged.
       * Values are NEVER logged.
       */

      console.log(
        "FACEBOOK EXCHANGE REQUEST:",
        {
          method,
          path,
          received_fields:
            receivedFields
        }
      );

      /*
       * ===================================================
       * Authorization code
       * ===================================================
       */

      const code =
        body?.code ||
        body?.authorization_code ||
        body?.auth_code;

      if (code) {
        return exchangeFacebookCode(
          code,
          res
        );
      }

      /*
       * ===================================================
       * Facebook access token
       * ===================================================
       */

      const facebookAccessToken =
        body?.facebook_access_token;

      const clientId =
        body?.client_id;

      if (
        facebookAccessToken
      ) {
        return exchangeFacebookAccessToken(
          facebookAccessToken,
          clientId,
          res
        );
      }

      /*
       * ===================================================
       * No supported credential
       * ===================================================
       */

      return json(res, 400, {
        error:
          "invalid_grant",

        code:
          2017,

        received_fields:
          receivedFields
      });
    }

    /*
     * =====================================================
     * ALTERNATIVE FACEBOOK EXCHANGE
     * =====================================================
     */

    if (
      path ===
        "/auth/facebook/exchange" ||
      path ===
        "/api/auth/facebook/exchange"
    ) {
      if (method !== "POST") {
        return json(res, 405, {
          status: "error",
          message:
            "Method Not Allowed"
        });
      }

      const body =
        await readBody(req);

      const receivedFields =
        body &&
        typeof body === "object"
          ? Object.keys(body)
          : [];

      console.log(
        "FACEBOOK ALTERNATIVE EXCHANGE:",
        {
          method,
          path,
          received_fields:
            receivedFields
        }
      );

      /*
       * Authorization code
       */

      const code =
        body?.code ||
        body?.authorization_code ||
        body?.auth_code;

      if (code) {
        return exchangeFacebookCode(
          code,
          res
        );
      }

      /*
       * Access token
       */

      const facebookAccessToken =
        body?.facebook_access_token;

      const clientId =
        body?.client_id;

      if (
        facebookAccessToken
      ) {
        return exchangeFacebookAccessToken(
          facebookAccessToken,
          clientId,
          res
        );
      }

      return json(res, 400, {
        status: "error",

        message:
          "Facebook authorization credential is required",

        received_fields:
          receivedFields
      });
    }

    /*
     * =====================================================
     * 404
     * =====================================================
     */

    return json(res, 404, {
      status: 404,

      message:
        "Endpoint not found",

      path:
        path
    });

  } catch (error) {
    console.error(
      "FUNCTION ERROR:",
      error?.stack ||
      error?.message ||
      error
    );

    return json(res, 500, {
      status: "error",

      message:
        "Internal server error"
    });
  }
};
