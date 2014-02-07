var OAuthToken = require('./oauth2').OAuthToken;

exports.find = function (key, done) {
  OAuthToken.findOne({
    accessToken: key
  }, done);
};

exports.save = function (token, clientId, resourceOwner, scopes, done) {
  OAuthToken.create({
    accessToken: token,
    clientId: clientId,
    resourceOwner: resourceOwner,
    scopes: scopes,
    issuedAt: new Date(),
    expiresIn: 3600
  }, done);
};
