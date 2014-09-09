var debug = require('debug')('loopback:oauth2:models');
/**
 * Create oAuth 2.0 metadata models
 * @param app
 * @param options
 */
module.exports = function(app, options) {
  var loopback = app.loopback;
  options = options || {};
  var userModel = options.userModel || loopback.getModelByType(loopback.User);
  var applicationModel = options.applicationModel
    || loopback.getModelByType(loopback.Application);

  var dataSource = options.dataSource;
  if(typeof dataSource === 'string') {
    dataSource = app.dataSources[dataSource];
  }

  var oauth2 = require('./oauth2-models')(dataSource);
  var oAuthTokenModel = oauth2.OAuthToken;
  var oAuthAuthorizationCodeModel = oauth2.OAuthAuthorizationCode;

  var users = {};
  users.find = function (id, done) {
    debug("users.find(" + id + ")");
    userModel.findOne({
      id: id
    }, done);
  };

  users.findByUsername = function (username, done) {
    debug("users.findByUsername(" + username + ")");
    userModel.findOne({
      username: username
    }, done);
  };

  users.save = function (id, username, password, done) {
    debug("users.save(" + username + ")");
    userModel.create({
      id: id,
      username: username,
      password: password
    }, done);
  };

  var clients = {};
  clients.find = clients.findByClientId = function (clientId, done) {
    applicationModel.findById(clientId, done);
  };

  var token = {};
  token.find = function (key, done) {
    oAuthTokenModel.findOne({
      accessToken: key
    }, done);
  };

  token.save = function (token, clientId, resourceOwner, scopes, done) {
    oAuthTokenModel.create({
      accessToken: token,
      clientId: clientId,
      resourceOwner: resourceOwner,
      scopes: scopes,
      issuedAt: new Date(),
      expiresIn: 3600
    }, done);
  };

  var code = {};
  code.findByCode = code.find = function(key, done) {
    oAuthAuthorizationCodeModel.findOne({
      code: key
    }, done);
  };

  code.save = function(code, clientID, redirectURI, userID, scopes, done) {
    oAuthAuthorizationCodeModel.create({
      code: code,
      scopes: scopes,
      redirectURI: redirectURI,
      resourceOwner: userID,
      clientId: clientID
    }, done);
  };

  // Adapter for the oAuth2 provider
  var models = {
    users: users,
    clients: clients,
    accessTokens: token,
    authorizationCodes: code
  };

  return models;
};

