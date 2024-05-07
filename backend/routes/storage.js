const express = require("express");
const router = express.Router();
const uploadMiddleware = require("../utils/handleStorage");
const {validatorGetItem} = require("../validators/storage");
const { createItem, getItems, deleteItem, getItem, updateItem } = require("../controller/storage");

//Obtener lista Items
router.get("/", getItems);

//Detalle de lista 
router.get("/:id", validatorGetItem, getItem);

//Borrar Lista
router.delete("/:id", validatorGetItem, deleteItem);

//Actualiar lista
router.put("/", updateItem);

// .single para enviar un solo archivo - .multi es para varios
router.post("/", uploadMiddleware.single("myfile"), createItem);
  

module.exports = router;
