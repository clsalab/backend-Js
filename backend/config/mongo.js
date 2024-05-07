const mongoose = require('mongoose');

const dbConnect = () => {
    
const DB_URI = process.env.DB_URI;
mongoose.connect(DB_URI)
  .then(() => {
    console.log('****Conexión exitosa BD_Mongo****');
    // Realiza otras operaciones después de la conexión si es necesario
  })
  .catch(error => {
    console.error('****Error al conectar a BD_Mongo:', error.message,'****');
  });
};
  module.exports =dbConnect;
