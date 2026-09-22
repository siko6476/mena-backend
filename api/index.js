module.exports = async (req, res) => {
  const path = req.url.split("?")[0];

  // الصفحة الرئيسية
  if (path === "/" || path === "/api" || path === "/api/") {
    return res.status(200).json({
      status: "online",
      server: "MENA",
      message: "MENA backend is active"
    });
  }

  // معلومات المشروع
  if (path === "/app/info/get") {
    return res.status(200).json({
      status: 0,
      client_log: false,
      server_region: "MENA"
    });
  }

  // Feedback
  if (path === "/app/feedback") {
    return res.status(200).json({
      status: "ok",
      service: "feedback",
      server_region: "MENA"
    });
  }

  // بدء تسجيل الدخول بواسطة Facebook
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
      "https://gconectn10.vercel.app/auth/facebook/callback";

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

  // Facebook Callback
  if (path === "/auth/facebook/callback") {
    const code = req.query?.code;

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
      "https://gconectn10.vercel.app/auth/facebook/callback";

    try {
      // تحويل code إلى Access Token
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

      const accessToken = tokenData.access_token;

      // جلب معلومات المستخدم
      const userUrl = new URL(
        "https://graph.facebook.com/v26.0/me"
      );

      userUrl.searchParams.set("fields", "id,name,email");
      userUrl.searchParams.set("access_token", accessToken);

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

  return res.status(404).json({
    status: 404,
    message: "Endpoint not found"
  });
};
