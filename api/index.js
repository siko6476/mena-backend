module.exports = async (req, res) => {
  const BASE_URL = "https://gconn10.vercel.app";

  const url = new URL(
    req.url,
    `https://${req.headers.host || "gconn10.vercel.app"}`
  );

  const path = url.pathname;

  // =========================
  // الصفحة الرئيسية
  // =========================
  if (path === "/" || path === "/api" || path === "/api/") {
    return res.status(200).json({
      status: 0,
      client_log: false
    });
  }

  // =========================
  // معلومات المشروع
  // =========================
  if (path === "/app/info/get") {
    return res.status(200).json({
      status: 0,
      client_log: false
    });
  }

  // =========================
  // Feedback
  // =========================
  if (path === "/app/feedback") {
    return res.status(200).json({
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

  // =========================
  // Connect
  // =========================
  if (path === "/connect") {
    return res.status(200).json({
      status: "ok",
      path: "/connect"
    });
  }

  // =========================
  // Facebook Login
  // =========================
  if (path === "/auth/facebook") {
    const appId = process.env.FB_APP_ID;

    if (!appId) {
      return res.status(500).json({
        status: "error",
        message: "FB_APP_ID is not configured"
      });
    }

    const redirectUri =
      process.env.FB_REDIRECT_URI ||
      `${BASE_URL}/auth/facebook/callback`;

    const params = new URLSearchParams({
      client_id: appId,
      redirect_uri: redirectUri,
      scope: "email,public_profile",
      response_type: "code"
    });

    return res.redirect(
      "https://www.facebook.com/v26.0/dialog/oauth?" +
      params.toString()
    );
  }

  // =========================
  // Facebook Callback
  // =========================
  if (path === "/auth/facebook/callback") {
    const code = url.searchParams.get("code");

    if (!code) {
      return res.status(400).json({
        status: "error",
        message: "No Facebook authorization code"
      });
    }

    const appId = process.env.FB_APP_ID;
    const appSecret = process.env.FB_APP_SECRET;

    if (!appId || !appSecret) {
      return res.status(500).json({
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
        "https://graph.facebook.com/v26.0/oauth/access_token"
      );

      tokenUrl.searchParams.set("client_id", appId);
      tokenUrl.searchParams.set("client_secret", appSecret);
      tokenUrl.searchParams.set("redirect_uri", redirectUri);
      tokenUrl.searchParams.set("code", code);

      const tokenResponse = await fetch(tokenUrl);
      const tokenData = await tokenResponse.json();

      if (!tokenResponse.ok || !tokenData.access_token) {
        console.error("FACEBOOK TOKEN ERROR:", tokenData);

        return res.status(500).json({
          status: "error",
          message: "Could not obtain Facebook access token"
        });
      }

      // =========================
      // جلب معلومات المستخدم
      // =========================
      const userUrl = new URL(
        "https://graph.facebook.com/v26.0/me"
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
        console.error("FACEBOOK USER ERROR:", userData);

        return res.status(500).json({
          status: "error",
          message: "Could not obtain Facebook user information"
        });
      }

      return res.status(200).json({
        status: "success",
        user: userData
      });

    } catch (error) {
      console.error("FACEBOOK ERROR:", error);

      return res.status(500).json({
        status: "error",
        message: "Facebook authentication failed"
      });
    }
  }

  // =========================
  // Endpoint غير معروف
  // =========================
  return res.status(404).json({
    status: 404,
    message: "Endpoint not found"
  });
};
