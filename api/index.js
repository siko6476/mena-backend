const axios = require("axios");

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

  // بدء Facebook Login
  if (path === "/auth/facebook") {
    const FB_APP_ID = process.env.FB_APP_ID;

    if (!FB_APP_ID) {
      return res.status(500).json({
        status: "error",
        message: "FB_APP_ID is not configured"
      });
    }

    const redirectUri =
      process.env.FB_REDIRECT_URI ||
      "https://gconectn10.vercel.app/auth/facebook/callback";

    const params = new URLSearchParams({
      client_id: FB_APP_ID,
      redirect_uri: redirectUri,
      scope: "email,public_profile",
      response_type: "code"
    });

    return res.redirect(
      `https://www.facebook.com/v26.0/dialog/oauth?${params.toString()}`
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

    const FB_APP_ID = process.env.FB_APP_ID;
    const FB_APP_SECRET = process.env.FB_APP_SECRET;

    if (!FB_APP_ID || !FB_APP_SECRET) {
      return res.status(500).json({
        status: "error",
        message: "Facebook environment variables are missing"
      });
    }

    const redirectUri =
      process.env.FB_REDIRECT_URI ||
      "https://gconectn10.vercel.app/auth/facebook/callback";

    try {
      // الحصول على Access Token
      const tokenResponse = await axios.get(
        "https://graph.facebook.com/v26.0/oauth/access_token",
        {
          params: {
            client_id: FB_APP_ID,
            client_secret: FB_APP_SECRET,
            redirect_uri: redirectUri,
            code: code
          },
          timeout: 10000
        }
      );

      const accessToken = tokenResponse.data.access_token;

      // الحصول على بيانات المستخدم
      const userResponse = await axios.get(
        "https://graph.facebook.com/v26.0/me",
        {
          params: {
            fields: "id,name,email",
            access_token: accessToken
          },
          timeout: 10000
        }
      );

      return res.status(200).json({
        status: "success",
        user: userResponse.data
      });
    } catch (error) {
      console.error(
        "FACEBOOK ERROR:",
        error.response?.data || error.message
      );

      return res.status(500).json({
        status: "error",
        message: "Facebook authentication failed"
      });
    }
  }

  // أي مسار غير معروف
  return res.status(404).json({
    status: 404,
    message: "Endpoint not found"
  });
};
