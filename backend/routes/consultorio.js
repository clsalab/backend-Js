const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/session");
const checkRol = require("../middleware/rol");
const {
  validatorCreateItem,
  validatorGetItem,
} = require("../validators/consultorio");
const { getItems, getItem, createItem, updateItem, deleteItem } = require("../controller/consultorio");

router.get("/", getItems);
//si tienes mas Id o variables "/:id/:var1/:var2"
router.get("/:id", validatorGetItem, getItem);
router.post("/", authMiddleware, checkRol(["admin","user"]), validatorCreateItem, createItem);
router.put("/:id", authMiddleware, checkRol(["admin","user"]), validatorGetItem, validatorCreateItem, updateItem);
router.delete("/:id", authMiddleware, checkRol(["admin","user"]), validatorGetItem,  deleteItem);

module.exports = router;
