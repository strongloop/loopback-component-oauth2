var OAuthAuthorizationCode = require('./oauth2').OAuthAuthorizationCode;

exports.find = function (key, done) {
  OAuthAuthorizationCode.findOne({
    code: key
  }, done);
};

exports.save = function (code, clientID, redirectURI, userID, scopes, done) {
  OAuthAuthorizationCode.create({
    code: code,
    scopes: scopes,
    redirectURI: redirectURI,
    resourceOwner: userID,
    clientId: clientID
  }, done);
};
