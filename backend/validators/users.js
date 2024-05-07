const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("username").exists().notEmpty(),
  check("useremail").exists().notEmpty(),
  check("userpassword").exists().notEmpty(),
  check("userestado").exists().notEmpty(),
  check("userroles").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
