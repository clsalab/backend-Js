const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("medTipoDoc").exists().notEmpty(),
  check("medNumDoc").exists().notEmpty(),
  check("medNombres").exists().notEmpty(),
  check("medApellidos").exists().notEmpty(),
  check("medEspecialidad").exists().notEmpty(),
  check("medFechaNacimiento").exists().notEmpty(),
  check("medSexo").exists().notEmpty(),
  check("medTelefono").exists().notEmpty(),
  check("medCorreo").exists().notEmpty(),
  check("medContraseña").exists().notEmpty(),
  check("medEstado").exists().notEmpty(),
  check("userroles").exists().notEmpty(),
];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
