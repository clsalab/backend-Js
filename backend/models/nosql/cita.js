const mongoose = require('mongoose');
const mongooseDelete = require("mongoose-delete");

const CitaSchema = new mongoose.Schema({
  citNumDocPaciente: { type: Number, required: true },
  citNombrePaciente: {type: String, required: true },
  citEPSPaciente: { type: String, required: true },
  citMedico: { type: String, required: true },
  citEspecialidad: { type: String, required: true },
  citFecha: { type: Date, required: true },
  citHora: { type: String, required: true },
  citColsultorio: { type: String, required: true },
  citEstado: {type: ["activa","atendida","cancelada"], default: "activa", },
  citObservacion: { type: String, required: true },
  citNumAprobaion: { type: Number, required: true, unique: true }
},
{
  timestamps:true, versionKey: false,
});

CitaSchema.plugin(mongooseDelete, {overrideMethods:"all"});
module.exports = mongoose.model('citas', CitaSchema);