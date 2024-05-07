const { check } = require("express-validator");
const validateResults = require("../utils/handleValidator");

/* const validatorCreateItem = [
  check("url").exists().notEmpty(),
  check("filename").exists().notEmpty(),
]; */
//NO es necesario crear una validacion para crear storage
//Ya que estan creada en el middleware

const validatorGetItem = [
  check("id").exists().notEmpty(),
  (req, res, next) => {
    return validateResults(req, res, next);
  },
];

module.exports = { validatorGetItem };
