var schema = require('./mongo_schema');

exports.users = require('./users');
exports.clients = require('./clients');
exports.accessTokens = require('./accesstokens');
exports.authorizationCodes = require('./authorizationcodes');

exports.users.findByUsername("bob", function(err, user) {
   if(user) {
       console.log("User found: " + JSON.stringify(user));
   } else {
       exports.users.save("bob", "bob", "secret", function(err, obj) {
          if (err) {
              console.log(err);
          }
          else {
              console.log("User created: " + JSON.stringify(obj));
          }
	   });
   }
});

exports.clients.findByClientId("abc123", function(err, client) {
   if(client) {
       console.log("Client found: " + JSON.stringify(client));
   } else {
       exports.clients.save("abc123_app", "abc123@sample.com", "abc123", null, null, null, "CONFIDENTIAL", "bob", function(err, obj) {
          if (err) {
              console.log(err);
          }
          else {
              console.log("User created: " + JSON.stringify(user));
          }
	   });
   }
});

