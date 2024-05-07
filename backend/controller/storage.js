const fs = require("fs");
const { storageModel } = require("../models");
const { handleHttpError } = require("../utils/handleError");
const { matchedData } = require("express-validator");

const PUBLIC_URL = process.env.PUBLIC_URL;
const MEDIA_PATH = `${__dirname}/../storage`;
//Obtener una lista de la BD
/**
 * @param {*} req
 * @param {*} res
 */
const getItems = async (req, res) => {
  try {
    const data = await storageModel.find({});

    res.send({ data });
  } catch (e) {
    handleHttpError(res, "ERROR_LISTAR_ITEMS");
  }
};

//Obtener una detalle de la BD
const getItem = async (req, res) => {
  try {
    const { id } = matchedData(req);
    const data = await storageModel.findById(id);

    res.send({ data });
  } catch (e) {
    handleHttpError(res, "ERROR_DETTALLE_ITEM");
  }
};

//Insertar un registro en la BD
const createItem = async (req, res) => {
  try{
    const { body, file } = req;
  console.log(file);
  const fileData = {
    filename: file.filename,
    url: `${PUBLIC_URL}/${file.filename}`,
  };
  const data = await storageModel.create(fileData);
  res.send({ data });
  }catch (e) {
    handleHttpError(res, "ERROR_CREAR_ITEM");
  }
  
};

//Actualizar un registro de  la BD
const updateItem = (req, res) => {};

//Eliminar un registro de la BD
const deleteItem = async (req, res) => {
  try {
    const { id } = matchedData(req);
    const dataFile = await storageModel.findById(id);
    await storageModel.deleteOne({_id:id})
    const {filename} = dataFile; // Nombre del archivo
    const filePath = `${MEDIA_PATH}/${filename}` // Ruta D:/PROYECTO...
    //para cambiar la forma de elminar comentamos esta linea -->//fs.unlink.....
    //y modificamos la linea await storage....({_id:id}) y delete se cambia por deleteOne
    //fs.unlinkSync(filePath); 
    const data = {
      filePath,
      deleted:1
    }
    res.send({ data });
  } catch (e) {
    handleHttpError(res, "ERROR_DETTALLE_ITEM");
  }
};

module.exports = { getItems, getItem, createItem, updateItem, deleteItem };
