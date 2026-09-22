module.exports = (req, res) => {
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

  return res.status(404).json({
    status: 404,
    message: "Endpoint not found"
  });
};
