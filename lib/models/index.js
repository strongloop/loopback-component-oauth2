// Copyright IBM Corp. 2014,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var debug = require('debug')('loopback:oauth2:models');
var helpers = require('../oauth2-helper');

/**
 * Create oAuth 2.0 metadata models
 * @param app
 * @param options
 */
module.exports = function(app, options) {
  var loopback = app.loopback;
  options = options || {};

  var dataSource = options.dataSource;
  if (typeof dataSource === 'string') {
    dataSource = app.dataSources[dataSource];
  }

  var oauth2 = require('./oauth2-models')(dataSource);

  var userModel = loopback.findModel(options.userModel) ||
    loopback.getModelByType(loopback.User);
  debug('User model: %s', userModel.modelName);
  var applicationModel = loopback.findModel(options.applicationModel) || loopback.getModelByType(loopback.Application);
  debug('Application model: %s', applicationModel.modelName);

  var oAuthTokenModel = oauth2.OAuthToken;
  var oAuthAuthorizationCodeModel = oauth2.OAuthAuthorizationCode;
  var oAuthPermissionModel = oauth2.OAuthPermission;

  oAuthTokenModel.belongsTo(userModel,
    {as: 'user', foreignKey: 'userId'});

  oAuthTokenModel.belongsTo(applicationModel,
    {as: 'application', foreignKey: 'appId'});

  oAuthAuthorizationCodeModel.belongsTo(userModel,
    {as: 'user', foreignKey: 'userId'});

  oAuthAuthorizationCodeModel.belongsTo(applicationModel,
    {as: 'application', foreignKey: 'appId'});

  oAuthPermissionModel.belongsTo(userModel,
    {as: 'user', foreignKey: 'userId'});

  oAuthPermissionModel.belongsTo(applicationModel,
    {as: 'application', foreignKey: 'appId'});

  var getTTL = typeof options.getTTL === 'function' ? options.getTTL :
    function(responseType, clientId, resourceOwner, scopes) {
      if (typeof options.ttl === 'function') {
        return options.ttl(responseType, clientId, resourceOwner, scopes);
      }
      if (typeof options.ttl === 'number') {
        return options.ttl;
      }
      if (typeof options.ttl === 'object' && options.ttl !== null) {
        return options.ttl[responseType];
      }
      switch (responseType) {
        case 'code':
          return 300;
        default:
          return 14 * 24 * 3600; // 2 weeks
      }
    };

  var users = {};
  users.find = function(id, done) {
    debug('users.find(' + id + ')');
    userModel.findOne({where: {
      id: id,
    }}, done);
  };

  users.findByUsername = function(username, done) {
    debug('users.findByUsername(' + username + ')');
    userModel.findOne({where: {
      username: username,
    }}, done);
  };

  users.findByUsernameOrEmail = function(usernameOrEmail, done) {
    debug('users.findByUsernameOrEmail(' + usernameOrEmail + ')');
    userModel.findOne({where: {
      or: [
        {username: usernameOrEmail},
        {email: usernameOrEmail},
      ],
    }}, done);
  };

  users.save = function(id, username, password, done) {
    debug('users.save(' + username + ')');
    userModel.create({
      id: id,
      username: username,
      password: password,
    }, done);
  };

  var clients = {};
  clients.find = clients.findByClientId = function(clientId, done) {
    applicationModel.findById(clientId, done);
  };

  var token = {};
  token.find = function(accessToken, done) {
    oAuthTokenModel.findOne({where: {
      id: accessToken,
    }}, done);
  };

  token.findByRefreshToken = function(refreshToken, done) {
    oAuthTokenModel.findOne({where: {
      refreshToken: refreshToken,
    }}, done);
  };

  token.delete = function(clientId, token, tokenType, done) {
    var where = {
      appId: clientId,
    };
    if (tokenType === 'access_token') {
      where.id = token;
    } else {
      where.refreshToken = token;
    }
    oAuthTokenModel.destroyAll(where, done);
  };

  token.save = function(token, clientId, resourceOwner, scopes, refreshToken, done) {
    var tokenObj;
    if (arguments.length === 2 && typeof token === 'object') {
      // save(token, cb)
      tokenObj = token;
      done = clientId;
    }
    var ttl = getTTL('token', clientId, resourceOwner, scopes);
    if (!tokenObj) {
      tokenObj = {
        id: token,
        appId: clientId,
        userId: resourceOwner,
        scopes: scopes,
        issuedAt: new Date(),
        expiresIn: ttl,
        refreshToken: refreshToken,
      };
    }
    tokenObj.expiresIn = ttl;
    tokenObj.issuedAt = new Date();
    tokenObj.expiredAt = new Date(tokenObj.issuedAt.getTime() + ttl * 1000);
    oAuthTokenModel.create(tokenObj, done);
  };

  var code = {};
  code.findByCode = code.find = function(key, done) {
    oAuthAuthorizationCodeModel.findOne({where: {
      id: key,
    }}, done);
  };

  code.delete = function(id, done) {
    oAuthAuthorizationCodeModel.destroyById(id, done);
  };

  code.save = function(code, clientId, redirectURI, resourceOwner, scopes, done) {
    var codeObj;
    if (arguments.length === 2 && typeof token === 'object') {
      // save(code, cb)
      codeObj = code;
      done = clientId;
    }
    var ttl = getTTL('code', clientId, resourceOwner, scopes);
    if (!codeObj) {
      codeObj = {
        id: code,
        appId: clientId,
        userId: resourceOwner,
        scopes: scopes,
        redirectURI: redirectURI,
      };
    }
    codeObj.expiresIn = ttl;
    codeObj.issuedAt = new Date();
    codeObj.expiredAt = new Date(codeObj.issuedAt.getTime() + ttl * 1000);
    oAuthAuthorizationCodeModel.create(codeObj, done);
  };

  var permission = {};
  permission.find = function(appId, userId, done) {
    oAuthPermissionModel.findOne({where: {
      appId: appId,
      userId: userId,
    }}, done);
  };

  /*
   * Check if a client app is authorized by the user
   */
  permission.isAuthorized = function(appId, userId, scopes, done) {
    permission.find(appId, userId, function(err, perm) {
      if (err) {
        return done(err);
      }
      if (!perm) {
        return done(null, false);
      }
      var ok = helpers.isScopeAuthorized(scopes, perm.scopes);
      var info = ok ? {authorized: true} : {};
      return done(null, ok, info);
    });
  };

  /*
   * Grant permissions to a client app by a user
   */
  permission.addPermission = function(appId, userId, scopes, done) {
    oAuthPermissionModel.findOrCreate({where: {
      appId: appId,
      userId: userId,
    }}, {
      appId: appId,
      userId: userId,
      scopes: scopes,
      issuedAt: new Date(),
    }, function(err, perm, created) {
      if (created) {
        return done(err, perm, created);
      } else {
        if (helpers.isScopeAuthorized(scopes, perm.scopes)) {
          return done(err, perm);
        } else {
          perm.updateAttributes({scopes: helpers.normalizeList(scopes)}, done);
        }
      }
    });
  };

  // Adapter for the oAuth2 provider
  var customModels = options.models || {};
  var models = {
    users: customModels.users || users,
    clients: customModels.clients || clients,
    accessTokens: customModels.accessTokens || token,
    authorizationCodes: customModels.authorizationCodes || code,
    permissions: customModels.permission || permission,
  };

  return models;
};
