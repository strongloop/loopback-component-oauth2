var loopback = require('loopback');
var debug = require('debug')('loopback:oauth2:user');

var userModel = loopback.getModelByType(loopback.User);

exports.find = function (id, done) {
  debug("users.find(" + id + ")");
  userModel.findOne({
    id: id
  }, done);
};

exports.findByUsername = function (username, done) {
  debug("users.findByUsername(" + username + ")");
  userModel.findOne({
    name: username
  }, done);
};

exports.save = function (id, username, password, done) {
  debug("users.save(" + username + ")");
  userModel.create({
    id: id,
    name: username,
    password: password
  }, done);
};


