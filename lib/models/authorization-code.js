module.exports = function (oauth2) {
  var OAuthAuthorizationCode = oauth2.OAuthAuthorizationCode;

  var code = {};
  code.findByCode = code.find = function (key, done) {
    OAuthAuthorizationCode.findOne({
      code: key
    }, done);
  };

  code.save = function (code, clientID, redirectURI, userID, scopes, done) {
    OAuthAuthorizationCode.create({
      code: code,
      scopes: scopes,
      redirectURI: redirectURI,
      resourceOwner: userID,
      clientId: clientID
    }, done);
  };
  return code;
};
