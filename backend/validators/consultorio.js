const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("conNombre").exists().notEmpty(),
  check("conUbicacion").notEmpty(),
  check("conEspecialidad").exists().notEmpty(),
  check("conEstado").exists().notEmpty(),
];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
