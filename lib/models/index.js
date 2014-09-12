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

  var getTTL = function(grantType, clientId, userId, scopes) {
    if (typeof options.ttl === 'function') {
      return options.ttl(grantType, clientId, userId, scopes);
    }
    if (typeof options.ttl === 'number') {
      return options.ttl;
    }
    if (typeof options.ttl === 'object' && options.ttl !== null) {
      return options.ttl[grantType];
    }
    switch (grantType) {
      case 'code':
        return 300;
      default:
        return 14 * 24 * 3600; // 2 weeks
    }
  };

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
    var ttl = getTTL('token', clientId, resourceOwner, scopes);
    oAuthTokenModel.create({
      accessToken: token,
      clientId: clientId,
      resourceOwner: resourceOwner,
      scopes: scopes,
      issuedAt: new Date(),
      expiresIn: ttl
    }, done);
  };

  var code = {};
  code.findByCode = code.find = function(key, done) {
    oAuthAuthorizationCodeModel.findOne({
      code: key
    }, done);
  };

  code.save = function(code, clientId, redirectURI, userId, scopes, done) {
    var ttl = getTTL('code', clientId, userId, scopes);
    oAuthAuthorizationCodeModel.create({
      code: code,
      scopes: scopes,
      redirectURI: redirectURI,
      resourceOwner: userId,
      clientId: clientId,
      issuedAt: new Date(),
      expiresIn: ttl
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

