const mongoose = require("mongoose");
//const mongooseDelete = require("mongoose-delete");

const Consultorio_Schema = new mongoose.Schema(
  {
    conNombre: { type: String, required: true },
    conUbicacion: {type: String, required: true},
    conEspecialidad: { type: String, required: true },
    conEstado: { type: ["activo", "inactivo"], default: "activo" },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

//Coonsultorio_Schema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model("consultorios_", Consultorio_Schema);