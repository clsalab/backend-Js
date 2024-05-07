const { handleHttpError } = require("../utils/handleError");

//Array con los roles permitidos

const checkRol = (rol) => (req, res, next) => {
  try {
    const { user } = req;
    console.log({ user });
    const rolesByUser = user.userroles;

    const checkValueRol = rol.some((rolSingle) =>
      rolesByUser.includes(rolSingle)
    );
    if (!checkValueRol) {
      handleHttpError(res, "USER_NOT_PERMISSION", 403);
      return;
    }
    next();
  } catch (e) {
    handleHttpError(res, "ERROR_PERMISO", 403);
  }
};

module.exports = checkRol;
