const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/session");
const checkRol = require("../middleware/rol");
const {loginCtrl, registerCtrl} = require("../controller/auth");
const { validatorRegisterItem, validatorLogin } = require("../validators/auth");





const {
  validatorCreateItem,
  validatorGetItem,
} = require("../validators/users");
const {
  getItems,
  getItem,
  createItem,
  updateItem,
  deleteItem,
} = require("../controller/users");

router.get("/", getItems);
//si tienes mas Id o variables "/:id/:var1/:var2"
router.get("/:id", validatorGetItem, getItem);
router.post("/", validatorCreateItem, createItem);
router.post("/", validatorCreateItem, createItem);
router.post("/register", validatorRegisterItem, registerCtrl);
router.post("/login", validatorLogin, loginCtrl);
router.put("/:id", validatorGetItem, validatorCreateItem, updateItem);
router.delete("/:id", authMiddleware, checkRol(["admin","user"]), validatorGetItem, deleteItem);

module.exports = router;
