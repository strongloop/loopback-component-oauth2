var schema = require('./mongo_schema');

var user = new schema.User({id: "bob", name: "bob", password: "secret"});
user.save( function (err) {
  if (err) {
      console.log(err);
  } 
  else {  
      console.log("User created: " + JSON.stringify(user));
  }
});

exports.find = function(id, done) {
  console.log("find("+ id +")");
  schema.User.findOne({id: id}, done);
};

exports.findByUsername = function(username, done) {
  console.log("findByUsername("+ username +")");
  schema.User.findOne({name: username}, done);
};
