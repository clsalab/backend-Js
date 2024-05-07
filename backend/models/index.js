const ENGINE_DB = process.env.ENGINE_DB;
const pathModels = ENGINE_DB === "nosql" ? "./nosql" : "./mysql";

const models = {
  usersModel: require(`${pathModels}/users`),
  pacienteModel: require(`${pathModels}/paciente`),
  medicoModel: require(`${pathModels}/medico`),
  ipsModel: require(`${pathModels}/ips`),
  consultorioModel: require(`${pathModels}/consultorio`),
  citaModel: require(`${pathModels}/cita`),
  storageModel: require(`${pathModels}/storage`),
};

module.exports = models;
