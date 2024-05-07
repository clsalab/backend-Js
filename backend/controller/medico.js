const { matchedData } = require("express-validator");
const { medicoModel } = require("../models");
const { handleHttpError } = require("../utils/handleError");

//Obtener una lista de la BD

const getItems = async (req, res) => {
  try {
    const user = req.user;
    const data = await medicoModel.find({});
    res.send({ data, user });
  } catch (e) {
    handleHttpError(res, "ERROR_GET_ITEMS");
  }
};

//Obtener un detalle de la BD
const getItem = async (req, res) => {
  try {
    req = matchedData(req);
    const { id } = req;
    const user = req.user;
    const data = await medicoModel.findById(id);
    res.send({ data, user });
  } catch (e) {
    handleHttpError(res, "ERROR_GET_ITEM");
  }
};

//Insertar un registro en la BD
const createItem = async (req, res) => {
  try {
    const body = matchedData(req);
    const user = req.user;
    const data = await medicoModel.create(body);
    res.send({ data, user });
  } catch (e) {
    handleHttpError(res, "ERROR_CREATE_ITEMS");
  }
};

//Actualizar un registro de  la BD
const updateItem = async (req, res) => {
  try {
    const { id, ...body } = matchedData(req);
    const user = req.user;
    const data = await medicoModel.findByIdAndUpdate(id, body, { new: true });
    res.send({ data, user });
  } catch (e) {
    handleHttpError(res, "ERROR_UPDATE_ITEM");
  }
};

//Eliminar un registro de la BD
const deleteItem = async (req, res) => {
  try {
    req = matchedData(req);
    const { id } = req;
    const user = req.user;
    const data = await medicoModel.delete({_id:id});
    res.send({ data, user });
  } catch (e) {
    handleHttpError(res, "ERROR_DELETE_ITEM");
  }
};
  
module.exports = { getItems, getItem, createItem, updateItem, deleteItem };
