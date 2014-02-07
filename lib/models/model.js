var loopback = require('loopback');
var oauth2 = require('./oauth2');
var model = exports;

model.getClient = function (clientId, clientSecret, callback) {

  var applicationModel = loopback.getModelByType(loopback.Application);
  if (!clientSecret) {
    applicationModel.findById(clientId, function (err, app) {
      var client = null;
      if (!err && app) {
        client = {
          clientId: app.id
        };
      }
      callback(err, client);
    });
  } else {
    applicationModel.authenticate(clientId, clientSecret, function (err, matchedKey) {
      var client = null;
      if (!err && matchedKey) {
        client = {
          clientId: clientId,
          clientSecret: matchedKey
        };
      }
      callback(err, client);
    });
  }

};

/*
 * Required to support password grant type
 */
model.getUser = function (username, password, callback) {
  var userModel = loopback.getModelByType(loopback.User);
  userModel.findOne({where: {username: username}}, function (err, user) {
    if (err) {
      callback(err);
    } else if (user) {
      user.hasPassword(password, function (err, isMatch) {
        if (err) {
          callback(err);
        } else if (isMatch) {
          callback(null, user);
        } else {
          callback(null, false);
        }
      });
    } else {
      callback(null);
    }
  });

};

model.grantTypeAllowed = function (clientId, grantType, callback) {
  process.nextTick(function () {
    callback(false, true);
  });
};

/*
 * Required
 */

model.getAccessToken = function (bearerToken, callback) {

  oauth2.OAuthToken.findById(bearerToken, function (err, token) {
    var tokenInfo = null;
    if (!err && token) {
      tokenInfo = {
        accessToken: token.accessToken,
        clientId: token.clientId,
        expires: token.expiresAt,
        userId: token.resourceOwner
      };
    }
    callback(err, tokenInfo);
  });
};

model.saveAccessToken = function (accessToken, clientId, userId, expires, callback) {
  oauth2.OAuthToken.create({
    accessToken: accessToken,
    clientId: clientId,
    resourceOwner: userId,
    expiresAt: expires
  }, callback);

};

model.getAuthCode = function (authCode, callback) {

  oauth2.OAuthAuthorizationCode.findById(authCode, function (err, code) {
    var tokenInfo = null;
    if (!err && code) {
      tokenInfo = {
        code: authCode.code,
        clientId: authCode.clientId,
        expires: authCode.expiresAt,
        userId: authCode.resourceOwner
      };
    }
    callback(err, tokenInfo);
  });
};

model.saveAuthCode = function (authCode, clientId, userId, expires, callback) {
  oauth2.OAuthAuthorizationCode.create({
    code: authCode,
    clientId: clientId,
    resourceOwner: userId,
    expiresAt: expires
  }, callback);

};

model.getRefreshToken = function (refreshToken, callback) {

  oauth2.OAuthToken.findOne({where: {refreshToken: refreshToken}}, function (err, token) {
    var tokenInfo = null;
    if (!err && token) {
      tokenInfo = {
        refreshToken: token.refreshToken,
        clientId: token.clientId,
        expires: token.expiresAt,
        userId: token.resourceOwner
      };
    }
    callback(err, tokenInfo);
  });
};

model.saveRefreshToken = function (refreshToken, clientId, userId, expires, callback) {
  oauth2.OAuthToken.create({
    refreshToken: refreshToken,
    clientId: clientId,
    resourceOwner: userId,
    expiresAt: expires
  }, callback);
};

model.revokeRefreshToken = function (refreshToken, callback) {
  oauth2.OAuthToken.deleteAll({where: {refreshToken: refreshToken}}, callback);
};

/*
 model.generateToken = function(type, callback) {

 };
 */


