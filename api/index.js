module.exports = (req, res) => {
  res.status(200).json({
    status: "online",
    server: "MENA",
    message: "MENA backend is active"
  });
};
