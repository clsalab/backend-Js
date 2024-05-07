const mongoose = require("mongoose");
const mongooseDelete = require("mongoose-delete");

const ConsultorioSchema = new mongoose.Schema(
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

ConsultorioSchema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model("consultorios", ConsultorioSchema);
