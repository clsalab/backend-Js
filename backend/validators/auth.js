const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorRegisterItem = [
  check("username").exists().notEmpty().isLength({ min: 3, max: 99 }),
  check("useremail").exists().notEmpty().isEmail(),
  check("userpassword").exists().notEmpty().isLength({ min: 3, max: 15 }),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

const validatorLogin = [
  check("useremail").exists().notEmpty().isEmail(),
  check("userpassword").exists().notEmpty().isLength({ min: 3, max: 15 }),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorRegisterItem, validatorLogin };
