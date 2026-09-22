module.exports = async (req, res) => {
  const path = req.url.split("?")[0];

  if (path === "/" || path === "/api" || path === "/api/") {
    return res.status(200).json({
      status: "online",
      server: "MENA",
      message: "MENA backend is active"
    });
  }

  if (path === "/app/info/get") {
    return res.status(200).json({
      status: 0,
      client_log: false,
      server_region: "MENA"
    });
  }

  if (path === "/app/feedback") {
    return res.status(200).json({
      status: "ok",
      service: "feedback",
      server_region: "MENA"
    });
  }

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

  if (path === "/auth/facebook/callback") {
    return res.status(200).json({
      status: "ok",
      message: "Facebook callback reached successfully",
      code_received: Boolean(req.query?.code)
    });
  }

  return res.status(404).json({
    status: 404,
    message: "Endpoint not found"
  });
};
