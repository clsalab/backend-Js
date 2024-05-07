const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();

const PATH_ROUTES = __dirname; //nos devuelve la dirección local de la ruta ej: D:/Proyecto/...

const removeExtension = (filename) => {  // Remover estencion de los archivos
    //ejemplo --> index.js queda [index, js]
    return filename.split('.').shift() //aqui se expecifica delimitados (.split('.'))
    //y con shift indicamos que selecione el nombre //ejemplo --> index.js queda [index, js]
} 

/* const removeExtension = (filename) => {
    const { name } = path.parse(filename);
    return name;
}; */

//Esta funcion nos devuleve un array con los nombre de los archivo dentro del directorio routes
fs.readdirSync(PATH_ROUTES).filter((file) => {   // Nos trae la rutas y sus archivos
    const name = removeExtension(file) // Archivo sin la extenxion
    if (name !== 'index') {   //name sin la extencion y file con la extencion
        console.log(`Cargando ruta ${name}`)
        try {
            //aqui ase uso del http:localhost:3001/api /name que seria el nombre de la route sin extención
            router.use(`/${name}`, require(`./${file}`));
        } catch (error) {
            console.error(`Error cargando ruta ${name}:`, error);
        }  // http:localhost:3000/api/name  --> nombre archivo
    }
}) 


module.exports = router;