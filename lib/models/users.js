var debug = require('debug')('loopback:oauth2:user');

module.exports = function (loopback) {
  var userModel = loopback.getModelByType(loopback.User);

  var user = {};
  user.find = function (id, done) {
    debug("users.find(" + id + ")");
    userModel.findOne({
      id: id
    }, done);
  };

  user.findByUsername = function (username, done) {
    debug("users.findByUsername(" + username + ")");
    userModel.findOne({
      username: username
    }, done);
  };

  user.save = function (id, username, password, done) {
    debug("users.save(" + username + ")");
    userModel.create({
      id: id,
      username: username,
      password: password
    }, done);
  };

  return user;
};


