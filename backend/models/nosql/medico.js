const mongoose = require("mongoose");
const mongooseDelete = require("mongoose-delete");

const MedicoSchema = new mongoose.Schema(
  {
    medTipoDoc: { type: String, required: true },
    medNumDoc: { type: Number, required: true, unique: true },
    medNombres: { type: String, required: true },
    medApellidos: { type: String, required: true },
    medEspecialidad: { type: String, required: true },
    medFechaNacimiento: { type: Date, required: true },
    medSexo: { type: String, required: true },
    medTelefono: { type: Number, required: true },
    medCorreo: { type: String, required: true },
    medContraseña: { type: String, required: true },
    medEstado: { type: ["activo", "inactivo"], default: "activo" },
    userroles: { type: ["user", "admin"], default: "admin" },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

MedicoSchema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model("medicos", MedicoSchema);
