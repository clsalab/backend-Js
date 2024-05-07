const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

const validatorCreateItem = [
  check("citNumDocPaciente").exists().notEmpty(),
  check("citNombrePaciente").exists().notEmpty(),
  check("citEPSPaciente").exists().notEmpty(),
  check("citMedico").exists().notEmpty(),
  check("citEspecialidad").exists().notEmpty(),
  check("citFecha").exists().notEmpty(),
  check("citHora").exists().notEmpty(),
  check("citColsultorio").exists().notEmpty(),
  check("citEstado").exists().notEmpty(),
  check("citObservacion").exists().notEmpty(),
  check("citNumAprobaion").exists().notEmpty(),

];

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorCreateItem, validatorGetItem };
