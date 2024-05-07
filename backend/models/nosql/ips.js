const mongoose = require('mongoose');
const mongooseDelete = require("mongoose-delete");

const IpsSchema = new mongoose.Schema({
  ipsNIT: { type: Number, required: true, unique: true },
  ipsNombres: { type: String, required: true },
  ipsFechaNacimiento: { type: Date, required: true },
  ipsTelefono: { type: Number, required: true },
  ipsCorreo: {type: String, required: true, validate: {validator: (req) => {return true;}, message: "Error correo",},},
  ipsEstado: {type: ["activo","inactivo"], default: "activo", }, 
},
{
  timestamps:true, versionKey: false,
});

IpsSchema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model('ips', IpsSchema);