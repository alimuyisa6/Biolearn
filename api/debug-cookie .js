module.exports = async (req, res) => {
  res.status(200).json({
    cookie: req.headers.cookie || null
  });
};
