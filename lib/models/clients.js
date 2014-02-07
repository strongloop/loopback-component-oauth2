var loopback = require('loopback');

var clientModel = loopback.getModelByType(loopback.Application);

exports.find = exports.findByClientId = function (key, done) {
  clientModel.findOne({
    clientId: key
  }, done);
};

