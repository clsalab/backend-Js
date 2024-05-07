const bcryptjs = require("bcryptjs");

//Contraseña sin encriptar .hash nos encripta
const encrypt = async (passwordPlain) => {
    
        const hash = await bcryptjs.hash(passwordPlain, 10)
        return hash;
    };


// Pasar contraseña si encriptar y encriptada
const compare = async(passwordPlain, hashPassword) => {
    return await bcryptjs.compare(passwordPlain, hashPassword)
}


module.exports = { encrypt, compare};