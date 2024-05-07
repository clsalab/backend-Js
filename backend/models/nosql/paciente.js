const mongoose = require('mongoose');
const mongooseDelete = require("mongoose-delete");

const PacienteSchema = new mongoose.Schema({
  pacTipoDoc: { type: String, required: true },
  pacNumDoc: { type: Number, required: true, unique: true },
  pacNombres: { type: String, required: true },
  pacApellidos: { type: String, required: true },
  pacFechaNacimiento: { type: Date, required: true },
  pacSexo: { type: String, required: true },
  pacTelefono: { type: Number, required: true },
  pacCorreo: {type: String, required: true, validate: {validator: (req) => {return true;}, message: "Error correo",},},
  pacEPS: { type: String, required: true },
  pacEstado: {type: ["activo","inactivo"], default: "activo", },
  pacContraseña: { type: String, required: true },
  userroles: {type: ["user","admin"], default: "user", }
 
},
{
  timestamps:true, versionKey: false,
});

PacienteSchema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model('pacientes', PacienteSchema);