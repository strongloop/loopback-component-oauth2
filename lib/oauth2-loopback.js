// Copyright IBM Corp. 2014,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
var SG = require('strong-globalize');
var g = SG();
var url = require('url'),
  oauth2Provider = require('./oauth2orize'),
  TokenError = require('./errors/tokenerror'),
  AuthorizationError = require('./errors/authorizationerror'),
  utils = require('./utils'),
  helpers = require('./oauth2-helper'),
  MacTokenGenerator = require('./mac-token'),
  modelBuilder = require('./models/index'),
  debug = require('debug')('loopback:oauth2'),
  passport = require('passport'),
  login = require('connect-ensure-login'),
  LocalStrategy = require('passport-local').Strategy,
  BasicStrategy = require('passport-http').BasicStrategy,
  ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
  ClientJWTBearerStrategy = require('./strategy/jwt-bearer').Strategy,
  bodyParser = require('body-parser');

var clientInfo = helpers.clientInfo;
var userInfo = helpers.userInfo;
var isExpired = helpers.isExpired;
var validateClient = helpers.validateClient;

var setupResourceServer = require('./resource-server');

/**
 *
 * @param {Object} app The app instance
 * @param {Object} options The options object
 * @property {Function} generateToken A custom function to generate tokens
 * @property {boolean} session
 * @property {String[]} supportedGrantTypes
 * @property {boolean} configureEndpoints
 * @returns {{}}
 */
module.exports = function(app, options) {
  options = options || {};
  var models = modelBuilder(app, options);

  var handlers = {};
  app._oauth2Handlers = handlers;

  // Default to true
  var session = (options.session !== false);

  app.middleware('auth:before', passport.initialize());
  if (session) {
    app.middleware('auth', passport.session());
  }

  if (options.resourceServer !== false) {
    handlers.authenticate = setupResourceServer(app, options, models, true);
  }

  if (options.authorizationServer === false) {
    // Skip the configuration of protocol endpoints
    return handlers;
  }

  var macTokenGenerator = new MacTokenGenerator('sha256');

  var generateToken = options.generateToken || function(options) {
    options = options || {};
    var id = utils.uid(32);
    if (options.client && options.client.tokenType === 'jwt') {
      var secret = options.client.clientSecret || options.client.restApiKey;
      var payload = {
        id: id,
        clientId: options.client.id,
        userId: options.user && options.user.id,
        scope: options.scope,
        createdAt: new Date(),
      };
      var token = helpers.generateJWT(payload, secret, 'HS256');
      return {
        id: token,
      };
    } else if (options.client && options.client.tokenType === 'mac') {
      options.jwtAlgorithm = 'HS256'; // HS256 for mac token
      return macTokenGenerator.generateToken(options);
    } else {
      return {
        id: id,
      };
    }
  };

  // create OAuth 2.0 server
  var server = oauth2Provider.createServer();

  /*
   Register serialization and deserialization functions.

   When a client redirects a user to user authorization endpoint, an
   authorization transaction is initiated.  To complete the transaction, the
   user must authenticate and approve the authorization request.  Because this
   may involve multiple HTTP request/response exchanges, the transaction is
   stored in the session.

   An application must supply serialization functions, which determine how the
   client object is serialized into the session.  Typically this will be a
   simple matter of serializing the client's ID, and deserializing by finding
   the client by ID from the database.
   */
  if (session) {
    server.serializeClient(function(client, done) {
      debug('serializeClient: %s', clientInfo(client));
      return done(null, client.id);
    });

    server.deserializeClient(function(id, done) {
      debug('deserializeClient: %s', id);
      models.clients.findByClientId(id, done);
    });
  }

  var supportedGrantTypes = options.supportedGrantTypes ||
    ['authorizationCode', 'implicit', 'clientCredentials',
      'resourceOwnerPasswordCredentials', 'refreshToken', 'jwt'];

  /*
   Register supported grant types.

   OAuth 2.0 specifies a framework that allows users to grant client
   applications limited access to their protected resources.  It does this
   through a process of the user granting access, and the client exchanging
   the grant for an access token.

   Grant authorization codes.  The callback takes the `client` requesting
   authorization, the `redirectURI` (which is used as a verifier in the
   subsequent exchange), the authenticated `user` granting access, and
   their response, which contains approved scope, duration, etc. as parsed by
   the application.  The application issues a code, which is bound to these
   values, and will be exchanged for an access token.
   */
  var codeGrant;
  if (supportedGrantTypes.indexOf('authorizationCode') !== -1) {
    codeGrant = server.grant(oauth2Provider.grant.code(
      {allowsPost: options.allowsPostForAuthorization},
      function(client, redirectURI, user, scope, ares, done) {
        if (validateClient(client, {
          scope: scope,
          redirectURI: redirectURI,
          grantType: 'authorization_code',
        }, done)) {
          return;
        }

        function generateAuthCode() {
          var code = generateToken({
            grant: 'Authorization Code',
            client: client,
            user: user,
            scope: scope,
            redirectURI: redirectURI,
          }).id;

          debug('Generating authorization code: %s %s %s %s %s',
            code, clientInfo(client), redirectURI, userInfo(user), scope);
          models.authorizationCodes.save(code, client.id, redirectURI,
            user.id,
            scope,
            function(err) {
              done(err, err ? null : code);
            });
        }

        if (ares.authorized) {
          generateAuthCode();
        } else {
          models.permissions.addPermission(client.id, user.id, scope,
            function(err) {
              if (err) {
                return done(err);
              }
              generateAuthCode();
            });
        }
      }));

    /*
     Exchange authorization codes for access tokens.  The callback accepts the
     `client`, which is exchanging `code` and any `redirectURI` from the
     authorization request for verification.  If these values are validated, the
     application issues an access token on behalf of the user who authorized the
     code.
     */
    server.exchange(oauth2Provider.exchange.code(
      function(client, code, redirectURI, done) {
        debug('Verifying authorization code: %s %s %s',
          code, clientInfo(client), redirectURI);

        models.authorizationCodes.findByCode(code, function(err, authCode) {
          if (err || !authCode) {
            return done(err);
          }

          debug('Authorization code found: %j', authCode);

          var clientId = authCode.appId || authCode.clientId;
          var resourceOwner = authCode.userId || authCode.resourceOwner;

          // The client id can be a number instead of string
          if (client.id != clientId) {
            return done(new TokenError(g.f('Client id mismatches'),
              'invalid_grant'));
          }
          if (redirectURI != authCode.redirectURI) {
            return done(new TokenError(g.f('Redirect {{uri}} mismatches'),
              'invalid_grant'));
          }

          if (isExpired(authCode)) {
            return done(new TokenError(g.f('Authorization code is expired'),
              'invalid_grant'));
          }

          var token = generateToken({
            grant: 'Authorization Code',
            client: client,
            scope: authCode.scopes,
            code: authCode,
            redirectURI: redirectURI,
          });

          var refreshToken = generateToken({
            grant: 'Authorization Code',
            client: client,
            code: authCode,
            scope: authCode.scopes,
            redirectURI: redirectURI,
            refreshToken: true,
          }).id;

          debug('Generating access token: %j %s %s',
            token, clientInfo(client), redirectURI);

          // Remove the authorization code
          models.authorizationCodes.delete(code, function(err) {
            if (err) return done(err);
            models.accessTokens.save(token.id, clientId,
              resourceOwner, authCode.scopes, refreshToken,
              getTokenHandler(token, done));
          });
        });
      }));
  }

  function userLogin(username, password, done) {
    debug('userLogin: %s', username);
    models.users.findByUsernameOrEmail(username, function(err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false);
      }
      user.hasPassword(password, function(err, matched) {
        if (err || !matched) {
          return done(err, false);
        }
        done(null, user);
      });
    });
  }

  function getTokenHandler(params, done) {
    return function(err, accessToken) {
      if (err || !accessToken) {
        return done(err);
      }
      done(null, accessToken.id, helpers.buildTokenParams(accessToken, params));
    };
  }

  /*
   * Handle password flow
   */
  if (supportedGrantTypes.indexOf('resourceOwnerPasswordCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.password(
      function(client, username, password, scope, done) {
        debug('Verifying username/password: %s %s %s',
          clientInfo(client), username, scope);

        if (validateClient(client, {
          scope: scope,
          grantType: 'password',
        }, done)) {
          return;
        }

        userLogin(username, password, function(err, user) {
          if (err || !user) {
            return done(err, null);
          }
          var token = generateToken({
            grant: 'Resource Owner Password Credentials',
            client: client,
            user: user,
            scope: scope,
          });

          var refreshToken = generateToken({
            grant: 'Resource Owner Password Credentials',
            client: client,
            user: user,
            scope: scope,
            refreshToken: true,
          }).id;

          debug('Generating access token: %j %s %s %s',
            token, clientInfo(client), username, scope);

          models.accessTokens.save(token.id, client.id, user.id,
            scope, refreshToken, getTokenHandler(token, done));
        });
      }));
  }

  /*
   * Client credentials flow
   */
  if (supportedGrantTypes.indexOf('clientCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.clientCredentials(
      function(client, subject, scope, done) {
        if (validateClient(client, {
          scope: scope,
          grantType: 'client_credentials',
        }, done)) {
          return;
        }

        function generateAccessToken(user) {
          var token = generateToken({
            grant: 'Client Credentials',
            client: client,
            user: user,
            scope: scope,
          });
          debug('Generating access token: %j %s %s',
            token, clientInfo(client), scope);

          var refreshToken = generateToken({
            grant: 'Client Credentials',
            client: client,
            user: user,
            scope: scope,
            refreshToken: true,
          }).id;

          models.accessTokens.save(
            token.id, client.id, user && user.id, scope, refreshToken,
            getTokenHandler(token, done));
        }

        if (subject) {
          models.users.findByUsernameOrEmail(subject, function(err, user) {
            if (err) {
              return done(err);
            }
            if (!user) {
              return done(new AuthorizationError(g.f(
                  'Invalid subject: %s', subject), 'access_denied'));
            }
            models.permissions.isAuthorized(client.id, user.id, scope,
              function(err, authorized) {
                if (err) {
                  return done(err);
                }
                if (authorized) {
                  generateAccessToken(user);
                } else {
                  return done(new AuthorizationError(g.f(
                      'Permission denied by %s', subject), 'access_denied'));
                }
              });
          });
        } else {
          generateAccessToken();
        }
      }));
  }

  /*
   * Refresh token flow
   */
  if (supportedGrantTypes.indexOf('refreshToken') !== -1) {
    server.exchange(oauth2Provider.exchange.refreshToken(
      function(client, refreshToken, scope, done) {
        if (validateClient(client, {
          scope: scope,
          grantType: 'refresh_token',
        }, done)) {
          return;
        }

        models.accessTokens.findByRefreshToken(refreshToken,
          function(err, accessToken) {
            if (err || !accessToken) {
              // Refresh token is not found
              return done(err, false);
            }
            if (accessToken.appId != client.id) {
              // The client id doesn't match
              return done(null, false);
            }

            // Test if scope is a subset of accessToken.scopes
            if (scope) {
              for (var i = 0, n = scope.length; i < n; i++) {
                if (accessToken.scopes.indexOf(scope[i]) === -1) {
                  return done(null, false);
                }
              }
            } else {
              scope = accessToken.scopes;
            }

            var token = generateToken({
              grant: 'Refresh Token',
              client: client,
              scope: scope,
            });

            var refreshToken = generateToken({
              grant: 'Refresh Token',
              client: client,
              scope: scope,
              refreshToken: true,
            }).id;

            debug('Generating access token: %j %s %s %j',
              token, clientInfo(client), scope, refreshToken);

            models.accessTokens.save(token.id, client.id, accessToken.userId,
              scope, refreshToken, getTokenHandler(token, done));
          });
      }));
  }

  var tokenGrant;
  if (supportedGrantTypes.indexOf('implicit') !== -1) {
    tokenGrant = server.grant(oauth2Provider.grant.token(
      {allowsPost: options.allowsPostForAuthorization},
      function(client, user, scope, ares, done) {
        if (validateClient(client, {
          scope: scope,
          grantType: 'implicit',
        }, done)) {
          return;
        }

        function generateAccessToken() {
          var token = generateToken({
            grant: 'Implicit',
            client: client,
            user: user,
            scope: scope,
          });
          debug('Generating access token: %j %s %s %s',
            token, clientInfo(client), userInfo(user), scope);

          models.accessTokens.save(token.id, client.id, user.id, scope, null,
            getTokenHandler(token, done));
        }

        if (ares.authorized) {
          generateAccessToken();
        } else {
          models.permissions.addPermission(client.id, user.id, scope,
            function(err) {
              if (err) {
                return done(err);
              }
              generateAccessToken();
            });
        }
      }));
  }

  var jwtAlgorithm = options.jwtAlgorithm || 'RS256';
  if (supportedGrantTypes.indexOf('jwt') !== -1) {
    var jwt = require('jws');

    server.exchange('urn:ietf:params:oauth:grant-type:jwt-bearer',
      oauth2Provider.exchange.jwt(function(client, jwtToken, done) {
        debug('Verifying JWT: %s %s', clientInfo(client), jwtToken);
        var pub = client.jwks || client.publicKey;
        var decodedJWT;
        try {
          if (jwt.verify(jwtToken, jwtAlgorithm, pub)) {
            decodedJWT = jwt.decode(jwtToken);
            debug('Decoded JWT: %j', decodedJWT);
          } else {
            done(new Error(g.f('Invalid {{JWT}}: %j', jwtToken)));
          }
        } catch (err) {
          return done(err);
        }
        // TODO - verify client_id, scope and expiration are valid
        var payload = JSON.parse(decodedJWT.payload);

        if (validateClient(client, {
          scope: payload.scope,
          grantType: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        }, done)) {
          return;
        }

        function generateAccessToken(user) {
          var token = generateToken({
            grant: 'JWT',
            client: client,
            user: user,
            claims: payload,
          });
          debug('Generating access token %j %s %s', token,
            clientInfo(client), jwtToken);
          // Check OAuthPermission model to see if it's pre-approved
          models.accessTokens.save(
            token.id, client.id, user && user.id, payload.scope, null,
            getTokenHandler(token, done));
        }

        if (payload.sub) {
          models.users.findByUsernameOrEmail(payload.sub, function(err, user) {
            if (err) {
              return done(err);
            }
            if (!user) {
              return done(new AuthorizationError(g.f(
                  'Invalid subject: %s', payload.sub), 'access_denied'));
            }
            models.permissions.isAuthorized(client.id, user.id, payload.scope,
              function(err, authorized) {
                if (err) {
                  return done(err);
                }
                if (authorized) {
                  generateAccessToken(user);
                } else {
                  done(new AuthorizationError(g.f(
                      'Permission denied by %s', payload.sub), 'access_denied'));
                }
              });
          });
        } else {
          generateAccessToken();
        }
      }));
  }

  /*
   user authorization endpoint

   `authorization` middleware accepts a `validate` callback which is
   responsible for validating the client making the authorization request.  In
   doing so, is recommended that the `redirectURI` be checked against a
   registered value, although security requirements may vary accross
   implementations.  Once validated, the `done` callback must be invoked with
   a `client` instance, as well as the `redirectURI` to which the user will be
   redirected after an authorization decision is obtained.

   This middleware simply initializes a new authorization transaction.  It is
   the application's responsibility to authenticate the user and render a dialog
   to obtain their approval (displaying details about the client requesting
   authorization).  We accomplish that here by routing through `ensureLoggedIn()`
   first, and rendering the `dialog` view.
   */
  handlers.authorization = [
    server.authorization(
      function(clientID, redirectURI, scope, responseType, done) {
        debug('Verifying client %s redirect-uri: %s scope: %s response-type: %s',
          clientID, redirectURI, scope, responseType);
        models.clients.findByClientId(clientID, function(err, client) {
          if (err || !client) {
            return done(err);
          }
          debug('Client found: %s', clientInfo(client));
          if (validateClient(client, {
            scope: scope,
            redirectURI: redirectURI,
            responseType: responseType,
          }, done)) {
            return;
          }
          return done(null, client, redirectURI);
        });
      }),
    // Ensure the user is logged in
    login.ensureLoggedIn({redirectTo: options.loginPage || '/login'}),
    // Check if the user has granted permissions to the client app
    function(req, res, next) {
      if (options.forceAuthorize) {
        return next();
      }
      var userId = req.oauth2.user.id;
      var clientId = req.oauth2.client.id;
      var scope = req.oauth2.req.scope;
      models.permissions.isAuthorized(clientId, userId, scope,
        function(err, authorized) {
          if (err) {
            return next(err);
          } else if (authorized) {
            req.oauth2.res = {};
            req.oauth2.res.allow = true;
            server._respond(req.oauth2, res, function(err) {
              if (err) {
                return next(err);
              }
              return next(new AuthorizationError(g.f(
                'Unsupported response type: %s', req.oauth2.req.type), 'unsupported_response_type'));
            });
          } else {
            next();
          }
        });
    },
    // Now try to render the dialog to approve client app's request for permissions
    function(req, res, next) {
      if (options.decisionPage) {
        var urlObj = {
          pathname: options.decisionPage,
          query: {
            transactionId: req.oauth2.transactionID,
            userId: req.oauth2.user.id,
            clientId: req.oauth2.client.id,
            scope: req.oauth2.req.scope,
            redirectURI: req.oauth2.redirectURI,
          },
        };
        return res.redirect(url.format(urlObj));
      }
      res.render(options.decisionView || 'dialog',
        {transactionId: req.oauth2.transactionID,
          user: req.user, client: req.oauth2.client,
          scopes: req.oauth2.req.scope,
          redirectURI: req.oauth2.redirectURI});
    },
    server.errorHandler({mode: 'indirect'}),
  ];

  /*
   user decision endpoint

   `decision` middleware processes a user's decision to allow or deny access
   requested by a client application.  Based on the grant type requested by the
   client, the above grant middleware configured above will be invoked to send
   a response.
   */
  handlers.decision = [
    login.ensureLoggedIn({redirectTo: options.loginPage || '/login'}),
    server.decision(),
  ];

  /*
   token endpoint

   `token` middleware handles client requests to exchange authorization grants
   for access tokens.  Based on the grant type being exchanged, the above
   exchange middleware will be invoked to handle the request.  Clients must
   authenticate when making requests to this endpoint.
   */
  handlers.token = [
    passport.authenticate(
      ['loopback-oauth2-client-password',
        'loopback-oauth2-client-basic',
        'loopback-oauth2-jwt-bearer'],
      {session: false}),
    server.token(),
    server.errorHandler(),
  ];

  handlers.revoke = [
    passport.authenticate(
      ['loopback-oauth2-client-password',
        'loopback-oauth2-client-basic',
        'loopback-oauth2-jwt-bearer'],
      {session: false}),
    server.revoke(function(client, token, tokenType, cb) {
      models.accessTokens.delete(client.id, token, tokenType, cb);
    }),
    server.errorHandler(),
  ];

  /**
   * BasicStrategy & ClientPasswordStrategy
   *
   * These strategies are used to authenticate registered OAuth clients.  They are
   * employed to protect the `token` endpoint, which consumers use to obtain
   * access tokens.  The OAuth 2.0 specification suggests that clients use the
   * HTTP Basic scheme to authenticate.  Use of the client password strategy
   * allows clients to send the same credentials in the request body (as opposed
   * to the `Authorization` header).  While this approach is not recommended by
   * the specification, in practice it is quite common.
   */

  function clientLogin(clientId, clientSecret, done) {
    debug('clientLogin: %s', clientId);
    models.clients.findByClientId(clientId, function(err, client) {
      if (err) {
        return done(err);
      }
      if (!client) {
        return done(null, false);
      }
      var secret = client.clientSecret || client.restApiKey;
      if (secret !== clientSecret) {
        return done(null, false);
      }
      return done(null, client);
    });
  }

  // Strategies for oauth2 client-id/client-secret login
  // HTTP basic
  passport.use('loopback-oauth2-client-basic', new BasicStrategy(clientLogin));
  // Body
  passport.use('loopback-oauth2-client-password',
    new ClientPasswordStrategy(clientLogin));

  /**
   * JWT bearer token
   */
  passport.use('loopback-oauth2-jwt-bearer', new ClientJWTBearerStrategy(
    {audience: options.tokenPath || '/oauth/token',
      jwtAlgorithm: jwtAlgorithm,
      passReqToCallback: true},
    function(req, iss, header, done) {
      debug('Looking up public key for %s', iss);
      models.clients.findByClientId(iss, function(err, client) {
        if (err) {
          return done(err);
        }
        if (!client) {
          return done(null, false);
        }
        req.client = client;
        return done(null, client.jwks || client.publicKey);
      });
    },
    function(req, iss, sub, payload, done) {
      process.nextTick(function() {
        if (validateClient(req.client, {
          scope: payload.scope,
          grantType: req.body.grant_type,
        }, done)) {
          return;
        }
        done(null, req.client);
      });
      /*
      models.clients.findByClientId(iss, function(err, client) {
        if (err) {
          return done(err);
        }
        if (!client) {
          return done(null, false);
        }
        return done(null, client);
      });
      */
    }
  ));

  // The urlencoded middleware is required for oAuth 2.0 protocol endpoints
  var oauth2Paths = [
    options.authorizePath || '/oauth/authorize',
    options.tokenPath || '/oauth/token',
    options.revokePath || '/oauth/revoke',
    options.decisionPath || '/oauth/authorize/decision',
    options.loginPath || '/login',
  ];
  app.middleware('parse', oauth2Paths,
    bodyParser.urlencoded({extended: false}));
  app.middleware('parse', oauth2Paths, bodyParser.json({strict: false}));

  // Set up the oAuth 2.0 protocol endpoints
  if (options.authorizePath !== false) {
    app.get(options.authorizePath || '/oauth/authorize', handlers.authorization);
    app.post(options.authorizePath || '/oauth/authorize', handlers.authorization);
  }
  if (options.decisionPath !== false) {
    app.post(options.decisionPath || '/oauth/authorize/decision', handlers.decision);
  }
  if (options.tokenPath !== false) {
    app.post(options.tokenPath || '/oauth/token', handlers.token);
  }
  if (options.revokePath !== false) {
    app.post(options.revokePath || '/oauth/revoke', handlers.revoke);
  }

  if (options.loginPath !== false) {
    /**
     * LocalStrategy
     *
     * This strategy is used to authenticate users based on a username and password.
     * Anytime a request is made to authorize an application, we must ensure that
     * a user is logged in before asking them to approve the request.
     */
    passport.use('loopback-oauth2-local', new LocalStrategy(userLogin));

    if (session) {
      passport.serializeUser(function(user, done) {
        debug('serializeUser %s', userInfo(user));
        done(null, user.id);
      });

      passport.deserializeUser(function(id, done) {
        debug('deserializeUser %s', id);
        models.users.find(id, function(err, user) {
          done(err, user);
        });
      });
    }

    // Set up the login handler
    app.post(options.loginPath || '/login',
      passport.authenticate('loopback-oauth2-local',
      {successReturnToOrRedirect: '/',
        failureRedirect: options.loginPage || '/login'}));
  }

  return handlers;
};
