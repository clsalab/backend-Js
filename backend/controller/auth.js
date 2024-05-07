const { matchedData } = require("express-validator");
const { encrypt, compare } = require("../utils/handlePassword");
const { tokenSign } = require("../utils/handleJwt");
const { handleHttpError } = require("../utils/handleError");
const { usersModel } = require("../models");

//Controlador para registrar usuario
const registerCtrl = async (req, res) => {
  try {
    req = matchedData(req);
    const userpassword = await encrypt(req.userpassword);
    const body = { ...req, userpassword };
    const dataUser = await usersModel.create(body); //crear un usuario BD
    dataUser.set("userpassword", undefined, { strict: false }); //ocultar contraseña

    const data = {
      token: await tokenSign(dataUser),
      user: dataUser, 
    };

    res.send({ data });
  } catch (e) {
    handleHttpError(res, "ERROR_REGISTER_USER");
  }
};



//
const loginCtrl = async (req, res) => {
  try {
    req = matchedData(req);
    const user = await usersModel
      .findOne({ useremail: req.useremail }).select('username useremail userpassword')
  
    if (!user) {
      handleHttpError(res, "USER_NOT_EXISTS", 404);
      return;
    }
    const hashPassword = user.get("userpassword");
    const check = await compare(req.userpassword, hashPassword);

    if (!check) {
      handleHttpError(res, "PÁSSWORD_INVALID", 401);
      return;
    }
    user.set("userpassword", undefined, { strict: false });
    const data = {
      token: await tokenSign(user),
      user:{
        _id: user._id,
        username: user.username,
        useremail: user.useremail,
      },
    };
    res.send({ data });
  } catch (e) {
    handleHttpError(res, "ERROR_LOGIN_USER");
  }
};

module.exports = { registerCtrl, loginCtrl };
