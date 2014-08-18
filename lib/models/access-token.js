module.exports = function (oauth2) {
  var OAuthToken = oauth2.OAuthToken;
  var token = {};
  token.find = function (key, done) {
    OAuthToken.findOne({
      accessToken: key
    }, done);
  };

  token.save = function (token, clientId, resourceOwner, scopes, done) {
    OAuthToken.create({
      accessToken: token,
      clientId: clientId,
      resourceOwner: resourceOwner,
      scopes: scopes,
      issuedAt: new Date(),
      expiresIn: 3600
    }, done);
  };

  return token;
};
