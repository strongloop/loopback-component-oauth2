var schema = require('./mongo_schema');

exports.find = function(key, done) {
    schema.OAuthToken.findOne({accessToken: key}, done);
};

exports.save = function(token, userID, clientID, done) {
  console.log("Saving " + token);
  var oauthToken = new schema.OAuthToken ({
    accessToken: token,
    resourceOwner: userID,
    clientId: clientID 
  });
  oauthToken.save(done);
};
