const crypto = require("crypto");

const BASE_URL =
  process.env.BASE_URL ||
  "https://gconectn10.vercel.app";

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  BASE_URL;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_IN_VERCEL";

const FB_API_VERSION = "v26.0";

function json(res, status, data) {
  return res.status(status).json(data);
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function createSession(user) {
  const payload = {
    sub: String(user.id),
    name: user.name || null,
    email: user.email || null,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
  };

  const encoded = base64url(JSON.stringify(payload));
  const signature = sign(encoded);

  return `${encoded}.${signature}`;
}

function verifySession(token) {
  try {
    if (!token || !token.includes(".")) {
      return null;
    }

    const parts = token.split(".");
    if (parts.length !== 2) {
      return null;
    }

    const encoded = parts[0];
    const receivedSignature = parts[1];

    const expectedSignature = sign(encoded);

    if (receivedSignature.length !== expectedSignature.length) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(receivedSignature),
        Buffer.from(expectedSignature)
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64").toString("utf8")
    );

    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function createState() {
  const payload = {
    nonce: crypto.randomBytes(32).toString("hex"),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600
  };

  const encoded = base64url(JSON.stringify(payload));
  const signature = sign(encoded);

  return `${encoded}.${signature}`;
}

function verifyState(state) {
  try {
    if (!state || !state.includes(".")) {
      return false;
    }

    const parts = state.split(".");
    if (parts.length !== 2) {
      return false;
    }

    const encoded = parts[0];
    const receivedSignature = parts[1];
    const expectedSignature = sign(encoded);

    if (receivedSignature.length !== expectedSignature.length) {
      return false;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(receivedSignature),
        Buffer.from(expectedSignature)
      )
    ) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64").toString("utf8")
    );

    return (
      payload.exp &&
      payload.exp >= Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

module.exports = async (req, res) => {
  const url = new URL(
    req.url,
    `https://${req.headers.host || "gconectn10.vercel.app"}`
  );

  const path = url.pathname;

  // =========================
  // الصفحة الرئيسية
  // =========================

  if (
    path === "/" ||
    path === "/api" ||
    path === "/api/"
  ) {
    return json(res, 200, {
      status: 0,
      client_log: false,
      service: "N10 Auth API"
    });
  }

  // =========================
  // معلومات المشروع
  // =========================

  if (path === "/app/info/get") {
    return json(res, 200, {
      status: 0,
      client_log: false
    });
  }

  // =========================
  // Connect
  // =========================

  if (path === "/connect") {
    return json(res, 200, {
      status: "ok",
      path: "/connect"
    });
  }

  // =========================
  // بدء Facebook Login
  // =========================

  if (path === "/auth/facebook") {
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

    const state = createState();

    const params = new URLSearchParams({
      client_id: appId,
      redirect_uri: redirectUri,
      scope: "email,public_profile",
      response_type: "code",
      state
    });

    return res.redirect(
      `https://www.facebook.com/${FB_API_VERSION}/dialog/oauth?${params.toString()}`
    );
  }

  // =========================
  // Facebook Callback
  // =========================

  if (path === "/auth/facebook/callback") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    const fbError = url.searchParams.get("error");
    const fbErrorDescription =
      url.searchParams.get("error_description");

    if (fbError) {
      return json(res, 400, {
        status: "error",
        message: "Facebook OAuth error",
        error: fbError,
        description: fbErrorDescription || null
      });
    }

    if (!code) {
      return json(res, 400, {
        status: "error",
        message: "No Facebook authorization code"
      });
    }

    if (!verifyState(state)) {
      return json(res, 400, {
        status: "error",
        message: "Invalid or expired OAuth state"
      });
    }

    const appId = process.env.FB_APP_ID;
    const appSecret = process.env.FB_APP_SECRET;

    if (!appId || !appSecret) {
      return json(res, 500, {
        status: "error",
        message: "Facebook environment variables are missing"
      });
    }

    const redirectUri =
      process.env.FB_REDIRECT_URI ||
      `${BASE_URL}/auth/facebook/callback`;

    try {
      // =========================
      // تحويل code إلى Access Token
      // =========================

      const tokenUrl = new URL(
        `https://graph.facebook.com/${FB_API_VERSION}/oauth/access_token`
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

      const tokenResponse = await fetch(tokenUrl);
      const tokenData = await tokenResponse.json();

      if (
        !tokenResponse.ok ||
        !tokenData.access_token
      ) {
        console.error(
          "FACEBOOK TOKEN ERROR:",
          tokenData
        );

        return json(res, 500, {
          status: "error",
          message: "Could not obtain Facebook access token"
        });
      }

      // =========================
      // جلب بيانات المستخدم
      // =========================

      const userUrl = new URL(
        `https://graph.facebook.com/${FB_API_VERSION}/me`
      );

      userUrl.searchParams.set(
        "fields",
        "id,name,email"
      );

      userUrl.searchParams.set(
        "access_token",
        tokenData.access_token
      );

      const userResponse = await fetch(userUrl);
      const userData = await userResponse.json();

      if (!userResponse.ok) {
        console.error(
          "FACEBOOK USER ERROR:",
          userData
        );

        return json(res, 500, {
          status: "error",
          message: "Could not obtain Facebook user information"
        });
      }

      // =========================
      // إنشاء Session لمشروعك
      // =========================

      const sessionToken =
        createSession(userData);

      // =========================
      // النتيجة
      // =========================

      return json(res, 200, {
        status: "success",

        user: {
          id: userData.id,
          name: userData.name || null,
          email: userData.email || null
        },

        session: {
          token: sessionToken,
          expires_in: 604800
        }
      });

    } catch (error) {
      console.error(
        "FACEBOOK ERROR:",
        error
      );

      return json(res, 500, {
        status: "error",
        message: "Facebook authentication failed"
      });
    }
  }

  // =========================
  // التحقق من Session
  // =========================

  if (path === "/auth/session") {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return json(res, 401, {
        status: "error",
        message: "Missing session token"
      });
    }

    const token =
      authorization.slice(7).trim();

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
      authenticated: true,
      user: {
        id: session.sub,
        name: session.name,
        email: session.email
      },
      expires_at: session.exp
    });
  }

  // =========================
  // Endpoint غير معروف
  // =========================

  return json(res, 404, {
    status: 404,
    message: "Endpoint not found"
  });
};
