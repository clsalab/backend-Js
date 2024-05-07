const mongoose = require("mongoose");
const mongooseDelete = require("mongoose-delete");

const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    useremail: { type: String, required: true, unique: true },
    userpassword: { type: String, required: true, select:false },
    userestado: { type: ["activo", "inactivo"], default: "activo" },
    userroles: { type: ["user", "admin"], default: "user" },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

UserSchema.plugin(mongooseDelete, { overrideMethods: "all" });
module.exports = mongoose.model("users", UserSchema); 
