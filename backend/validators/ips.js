const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("ipsNIT").exists().notEmpty(),
  check("ipsNombres").exists().notEmpty(),
  check("ipsFechaNacimiento").exists().notEmpty(),
  check("ipsTelefono").exists().notEmpty(),
  check("ipsCorreo").exists().notEmpty(),
  check("ipsCorreo").exists().notEmpty(),
  check("ipsEstado").exists().notEmpty(),
];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
