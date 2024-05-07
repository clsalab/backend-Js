const multer = require("multer");
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const pathStorage = `${__dirname}/../storage`;
      cb(null, pathStorage);
    },
    // crea cualquier tipo de archivo
    //.split divide nos separa la extensión del archivo
    //.pop selecciona la extensión, último ejemplo: ["storage", "pdf"]
    filename: function (req, file, cb) {
      const ext = file.originalname.split(".").pop();
      const filename = `file-${Date.now()}.${ext}`;
      cb(null, filename);
    },
  });
  
  const uploadMiddleware = multer({storage});

  module.exports = uploadMiddleware;