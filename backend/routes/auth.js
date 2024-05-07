//Ruta de autentificación

const express = require("express");
const { registerCtrl, loginCtrl} = require("../controller/auth");
const router = express.Router();
const { validatorRegisterItem, validatorLogin } = require("../validators/auth");

//crear un registro
//con esto decimos estamos //htp://localhost:3001/api/login
router.post("/register", validatorRegisterItem, registerCtrl);
router.post("/login", validatorLogin, loginCtrl);


module.exports = router;