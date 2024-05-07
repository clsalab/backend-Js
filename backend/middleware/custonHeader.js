const custonHeader = (req, res, next) => {
  try {
    const apikey = req.headers.api_key;
    if (apikey === "leifer-01") {
      next();
    } else {
      res.status(403);
      res.send({ error: "API_KEY_NO_ES_CORRECTO" });
    }
  } catch (e) {
    res.status(403);
    res.send({ error: "ALGO_OCURRIO_EN_EL_CUSTOM_HEADER" });
  }
};

module.exports = custonHeader;
