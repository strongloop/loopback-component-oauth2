var async = require('async')
  , oauth2Provider = require('./oauth2orize')
  , scopeValidator = require('./scope')
  , helpers = require('./oauth2-helper')
  , TokenError = require('./errors/tokenerror')
  , debug = require('debug')('loopback:oauth2')
  , passport = require('passport')
  , BearerStrategy = require('passport-http-bearer').Strategy
  , ClientJWTBearerStrategy = require('./strategy/jwt-bearer').Strategy;

var clientInfo = helpers.clientInfo;
var userInfo = helpers.userInfo;
var isExpired = helpers.isExpired;

module.exports = setupResourceServer;

/**
 * Set up oAuth 2.0 strategies
 * @param {Object} app App instance
 * @param {Object} options Options
 * @param {Object} models oAuth 2.0 metadata models
 * @param {Boolean} jwt if jwt-bearer should be enabled
 * @returns {Function}
 */
function setupResourceServer(app, options, models, jwt) {
  /**
   * BearerStrategy
   *
   * This strategy is used to authenticate users based on an access token (aka a
   * bearer token).  The user must have previously authorized a client
   * application, which is issued an access token to make requests on behalf of
   * the authorizing user.
   */
  passport.use(new BearerStrategy({passReqToCallback: true},
      function(req, accessToken, done) {
        debug('Verifying access token %s', accessToken);
        models.accessTokens.find(accessToken, function(err, token) {
          if (err || !token) {
            return done(err);
          }

          debug('Access token found: %j', token);

          if (isExpired(token)) {
            return done(new TokenError('Access token is expired',
              'invalid_grant'));
          }

          var userId = token.userId || token.resourceOwner;
          var appId = token.appId || token.clientId;

          var user, app;
          async.parallel([
            function lookupUser(done) {
              if (userId == null) {
                return process.nextTick(done);
              }
              models.users.find(userId, function(err, u) {
                if (err) {
                  return done(err);
                }
                if (!u) {
                  return done(
                    new TokenError('Access token has invalid user id: ' +
                      userId, 'invalid_grant'));
                }
                debug('User found: %s', userInfo(u));
                user = u;
                done();
              });
            },
            function lookupApp(done) {
              if (appId == null) {
                return process.nextTick(done);
              }
              models.clients.find(appId, function(err, a) {
                if (err) {
                  return done(err);
                }
                if (!a) {
                  return done(
                    new TokenError('Access token has invalid app id: ' + appId,
                      'invalid_grant'));
                }
                debug('Client found: %s', clientInfo(a));
                app = a;
                done();
              });
            }], function(err) {
            if (err) {
              return done(err);
            }
            var authInfo = { accessToken: token, user: user, app: app };
            req.accessToken = token;
            done(null, user || {}, authInfo);
          });
        });
      })
  );

  /**
   * JWT bearer token
   */
  if (jwt) {
    passport.use('oauth2-jwt-bearer', new ClientJWTBearerStrategy(
      {audience: options.tokenPath || '/oauth/token', passReqToCallback: true},
      function(req, iss, header, done) {
        debug('Looking up public key for %s', iss);
        models.clients.findByClientId(iss, function(err, client) {
          if (err) {
            return done(err);
          }
          if (!client) {
            return done(null, false);
          }
          return done(null, client.publicKey);
        });
      },
      function(req, iss, sub, payload, done) {
        models.clients.findByClientId(iss, function(err, client) {
          if (err) {
            return done(err);
          }
          if (!client) {
            return done(null, false);
          }
          return done(null, client);
        });
      }
    ));
  }

  /**
   * Return the middleware chain to enforce oAuth 2.0 authentication and
   * authorization
   * @param {Object} [options] Options object
   * - scope
   * - jwt
   */
  function authenticate(options) {
    options = options || {};

    var authenticators = [];
    var scopeHandler = scopeValidator(options.scope);
    authenticators = [passport.authenticate('bearer', options)];
    if (jwt && options.jwt) {
      authenticators.push(passport.authenticate('oauth2-jwt-bearer', options));
    }
    if (options.scope) {
      authenticators.push(scopeHandler);
    }
    authenticators.push(oauth2Provider.errorHandler());
    return authenticators;
  }

  return authenticate;
}