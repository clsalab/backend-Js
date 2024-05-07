const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("pacTipoDoc").exists().notEmpty(),
  check("pacNumDoc").exists().notEmpty(),
  check("pacNombres").exists().notEmpty(),
  check("pacApellidos").exists().notEmpty(),
  check("pacFechaNacimiento").exists().notEmpty(),
  check("pacSexo").exists().notEmpty(),
  check("pacTelefono").exists().notEmpty(),
  check("pacCorreo").exists().notEmpty(),
  check("pacEPS").exists().notEmpty(),
  check("pacEstado").exists().notEmpty(),
  check("pacContraseña").exists().notEmpty(),
  check("userroles").exists().notEmpty(),
];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
