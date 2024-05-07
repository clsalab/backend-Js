const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const getProperties = require("../utils/handlePropertiesEngine");
const propertieskey = getProperties();

//Firmar - Generar token
//Debe pasar el objeto del usuario
const tokenSign = async (users) => {
  const sign = jwt.sign(
    {
      [propertieskey.id]: users[propertieskey.id],
      role: users.role,
    },
    JWT_SECRET,
    {
      expiresIn: "2h",
    }
  );
  return sign;
};

// Verificar token
// Debe pasar el token de sesión JWT
const verifyToken = async (tokenJwt) => {
  try {
    return jwt.verify(tokenJwt, JWT_SECRET);
  } catch (e) {
    return null;
  }
};


module.exports = { tokenSign, verifyToken };



