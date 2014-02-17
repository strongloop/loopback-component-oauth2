var loopback = require('loopback');

var clientModel = loopback.getModelByType(loopback.Application);

exports.find = exports.findByClientId = function (clientId, done) {
  clientModel.findById(clientId, done);
};

