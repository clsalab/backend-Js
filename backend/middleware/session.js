const { handleHttpError } = require("../utils/handleError");
const { verifyToken } = require("../utils/handleJwt");
const { usersModel } = require("../models");
const getProperties = require("../utils/handlePropertiesEngine");
const propertieskey = getProperties();

const authMiddleware = async (req, res, next) => {
  try {
    if (!req.headers.authorization) {
      handleHttpError(
        res,
        "NEED_SESSION NOT_TOKEN",
        401,
        "Authorization header is missing"
      );
      return;
    }
//Esto devuolve un array : bear toke, .split separamos bear del toke y 
//con pop le decimos que seleeciones el ultimo osea el token
    const token = req.headers.authorization.split(" ").pop();
    const dataToken = await verifyToken(token);

    // Aquí, en lugar de verificar solo la existencia de _id, puedes realizar una validación más específica del token

    if (!dataToken) {
      handleHttpError(res, "INVALID_TOKEN", 401, "Invalid token");
      return;
    }
    const query = {
      [propertieskey.id]: dataToken[propertieskey.id]
    };
    //Validar que usuario realizo la peticion
    const user = await usersModel.findOne(query);
    if (user) {
      // Agrega detalles adicionales del usuario al objeto req.user
      req.user = {
        _id: user._id,
        username: user.username, // Asegúrate de que el modelo tenga el campo 'username'
        useremail: user.useremail,
      };
    }
    next();
  } catch (e) {
    // Proporciona un mensaje de error más descriptivo en caso de excepción
    handleHttpError(
      res,
      "INTERNAL_SERVER_ERROR",
      500,
      e.message || "Internal server error"
    );
  }
};

const isValidToken = (dataToken) => {
  // Realiza la validación específica del token según tus requisitos
  // Por ejemplo, puedes verificar la expiración, la firma, u otros detalles específicos
  return dataToken && dataToken._id;
};

module.exports = authMiddleware;
