var schema = require('./mongo_schema');

exports.find = function(key, done) {
    schema.ClientRegistration.findOne({id: key}, done);
};

exports.save = function(name, email, description, url, iconURL, redirectURIs, type, userId, done) {

    var clientId = "abc123";
    var clientSecret = "ssh-secret";

    var client = new schema.ClientRegistration ({
    clientId: clientId,
    clientSecret: clientSecret,
    defaultTokenType: "Bearer",
    accessLevel: 1, 
    disabled: false,
    name: name,
    email: email,
    description: description,
    url: url,
    iconURL: iconURL,
    redirectURIs: redirectURIs,
    type: "CONFIDENTIAL",
    userId: userId,
  });
  client.save(done);
};

exports.findByClientId = function(clientID, done) {
    schema.ClientRegistration.findOne({clientId: clientID}, done);
};

