var schema = require('./mongo_schema');

exports.find = function(id, done) {
  console.log("find("+ id +")");
  schema.User.findOne({id: id}, done);
};

exports.findByUsername = function(username, done) {
  console.log("findByUsername("+ username +")");
  schema.User.findOne({name: username}, done);
};

exports.save = function(id, username, password, done) {
  console.log("Saving user: " + username);
  var user = new schema.User ({
    id: id,
    username: username,
    password: password
  });
  user.save(done);
};

