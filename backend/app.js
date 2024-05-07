require("dotenv").config();  //Usar variables de entorno -> .env
const express = require("express");
const cors = require("cors");  //Para interpretación entre navegadores
const dbConnectNoSql = require("./config/mongo");
//const {dbConnectMysql} = require("./config/mysql");
const app = express();

const ENGINE_DB = process.env.ENGINE_DB;  

app.use(cors());
app.use(express.json()); //Para recibir json de los post
app.use(express.static("storage")); //use los datos publicos desde storage

const port = process.env.PORT || 3000;
//Aqui invocamos la ruta - http:localhost:3001/api ./routes -> deforma inteligente seleciona la ruta
// Llamando al index.js que se encuentra dentro del directorio routes
app.use("/api", require("./routes"));

app.listen(port, () => {
  console.log("Tu app esta lista por el http://localhost:" + port);
});
(ENGINE_DB === "nosql") ? dbConnectNoSql () : dbConnectMysql();



