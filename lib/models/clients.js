module.exports = function (loopback) {

  var clientModel = loopback.getModelByType(loopback.Application);

  var clients = {};
  clients.find = clients.findByClientId = function (clientId, done) {
    clientModel.findById(clientId, done);
  };
  return clients;
};

