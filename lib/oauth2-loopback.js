/**
 * Module dependencies.
 */
var url = require('url')
  , async = require('async')
  , oauth2Provider = require('./oauth2orize')
  , scopeValidator = require('./scope')
  , TokenError = require('./errors/tokenerror')
  , utils = require('./utils')
  , modelBuilder = require('./models/index')
  , debug = require('debug')('loopback:oauth2')
  , passport = require('passport')
  , login = require('connect-ensure-login')
  , LocalStrategy = require('passport-local').Strategy
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
  , BearerStrategy = require('passport-http-bearer').Strategy
  , ClientJWTBearerStrategy = require('./strategy/jwt-bearer').Strategy;

function clientInfo(client) {
  if (!client) {
    return client;
  }
  return client.id + ',' + client.name;
}

function userInfo(user) {
  if (!user) {
    return user;
  }
  return user.id + ',' + user.username + ',' + user.email;
}

function isExpired(tokenOrCode) {
  var issuedTime =
    (tokenOrCode.issuedAt && tokenOrCode.issuedAt.getTime()) || -1;
  var now = Date.now();
  var expirationTime =
    (tokenOrCode.expiredAt && tokenOrCode.expiredAt.getTime()) || -1;
  if (expirationTime === -1 && issuedTime !== -1 &&
    typeof tokenOrCode.expiresIn === 'number') {
    expirationTime = issuedTime + tokenOrCode.expiresIn * 1000;
  }
  return now > expirationTime;
}

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
            done(null, user, authInfo);
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
      function(req, iss, header, done) {
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
   * Return the middleware chain to enfore oAuth 2.0 authentication and
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

  var generateToken = options.generateToken || function(options) {
    return utils.uid(32);
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
  if (supportedGrantTypes.indexOf('authorizationCode') !== -1) {
    server.grant(oauth2Provider.grant.code(
      { allowsPost: options.allowsPostForAuthorization},
      function(client, redirectURI, user, scope, ares, done) {
        var code = generateToken({
          grant: 'Authorization Code',
          client: client,
          user: user,
          scope: scope,
          redirectURI: redirectURI
        });

        debug('Generating authorization code: %s %s %s %s %s',
          code, clientInfo(client), redirectURI, userInfo(user), scope);
        models.authorizationCodes.save(code, client.id, redirectURI, user.id,
          scope,
          function(err) {
            done(err, err ? null : code);
          });
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

          debug('Authorization code found: %s', authCode);

          var clientId = authCode.appId || authCode.clientId;
          var resourceOwner = authCode.userId || authCode.resourceOwner;

          // The client id can be a number instead of string
          if (client.id != clientId) {
            return done(new TokenError('Client id mismatches',
              'invalid_grant'));
          }
          if (redirectURI !== authCode.redirectURI) {
            return done(new TokenError('Redirect uri mismatches',
              'invalid_grant'));
          }

          if (isExpired(authCode)) {
            return done(new TokenError('Authorization code is expired',
              'invalid_grant'));
          }

          var token = generateToken({
            grant: 'Authorization Code',
            client: client,
            code: authCode,
            redirectURI: redirectURI
          });

          var refreshToken = generateToken({
            grant: 'Authorization Code',
            client: client,
            scope: authCode.scopes,
            redirectURI: redirectURI
          });

          debug('Generating access token: %s %s %s',
            token, clientInfo(client), redirectURI);

          models.accessTokens.save(token, clientId,
            resourceOwner, authCode.scopes, refreshToken,
            function(err, accessToken) {
              done(err, err ? null : token, {
                refresh_token: refreshToken,
                expires_in: accessToken.expiresIn,
                scope: accessToken.scopes && accessToken.scopes.join(' ')
              });
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

  /*
   * Handle password flow
   */
  if (supportedGrantTypes.indexOf('resourceOwnerPasswordCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.password(
      function(client, username, password, scope, done) {
        debug('Verifying username/password: %s %s %s',
          clientInfo(client), username, scope);

        userLogin(username, password, function(err, user) {
          if (err || !user) {
            return done(err, null);
          }
          var token = generateToken({
            grant: 'Resource Owner Password Credentials',
            client: client,
            user: user,
            scope: scope
          });

          var refreshToken = generateToken({
            grant: 'Resource Owner Password Credentials',
            client: client,
            user: user,
            scope: scope
          });

          debug('Generating access token: %s %s %s %s',
            token, clientInfo(client), username, scope);

          models.accessTokens.save(token, client.id, user.id,
            scope, refreshToken,
            function(err, accessToken) {
              done(err, err ? null : token, {
                refresh_token: refreshToken,
                expires_in: accessToken.expiresIn,
                scope: scope && scope.join(' ')
              });
            });
        });
      }));
  }

  /*
   * Client credentials flow
   */
  if (supportedGrantTypes.indexOf('clientCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.clientCredentials(
      function(client, scope, done) {
        var token = generateToken({
          grant: 'Client Credentials',
          client: client,
          scope: scope
        });
        debug('Generating access token: %s %s %s',
          token, clientInfo(client), scope);

        var refreshToken = generateToken({
          grant: 'Client Credentials',
          client: client,
          scope: scope
        });

        models.accessTokens.save(token, client.id, null, scope, refreshToken,
          function(err, accessToken) {
            done(err, err ? null : token, {
              refresh_token: refreshToken,
              expires_in: accessToken.expiresIn,
              scope: scope && scope.join(' ')
            });
          });
      }));
  }

  /*
   * Refresh token flow
   */
  if (supportedGrantTypes.indexOf('refreshToken') !== -1) {
    server.exchange(oauth2Provider.exchange.refreshToken(
      function(client, refreshToken, scope, done) {
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
              scope: scope
            });

            var refreshToken = generateToken({
              grant: 'Resource Owner Password Credentials',
              client: client,
              scope: scope
            });

            debug('Generating access token: %s %s %s %j',
              token, clientInfo(client), scope, refreshToken);

            models.accessTokens.save(token, client.id, accessToken.userId,
              scope, refreshToken,
              function(err, accessToken) {
                done(err, err ? null : token, {
                  refresh_token: refreshToken,
                  expires_in: accessToken.expiresIn,
                  scope: scope && scope.join(' ')
                });
              });
          });
      }));
  }

  if (supportedGrantTypes.indexOf('implicit') !== -1) {
    server.grant(oauth2Provider.grant.token(
      { allowsPost: options.allowsPostForAuthorization},
      function(client, user, scope, ares, done) {
        var token = generateToken({
          grant: 'Implicit',
          client: client,
          user: user,
          scope: scope
        });
        debug('Generating access token: %s %s %s %s',
          token, clientInfo(client), userInfo(user), scope);

        models.accessTokens.save(token, client.id, user.id, scope, null,
          function(err) {
            done(err, err ? null : token);
          });
      }));
  }

  if (supportedGrantTypes.indexOf('jwt') !== -1) {
    var jwt = require('jws');

    server.exchange('urn:ietf:params:oauth:grant-type:jwt-bearer',
      oauth2Provider.exchange.jwt(function(client, jwtToken, done) {

        debug('Verifying JWT: %s %s', clientInfo(client), jwtToken);
        var pub = client.publicKey;
        var decodedJWT;
        try {
          if (jwt.verify(jwtToken, pub)) {
            decodedJWT = jwt.decode(jwtToken);
            debug('Decoded JWT: %j', decodedJWT);
          } else {
            done(new Error('Invalid JWT: ' + jwtToken));
          }
        } catch (err) {
          return done(err);
        }
        // TODO - verify client_id, scope and expiration are valid
        var payload = JSON.parse(decodedJWT.payload);
        // payload.iss == client.id
        var token = generateToken({
          grant: 'JWT',
          client: client,
          claims: payload
        });
        debug('Generating access token %s %s %s', token,
          clientInfo(client), jwtToken);
        // FIXME: [rfeng] Map payload.sub to userId
        // Check OAuthPermission model to see if it's pre-approved
        models.accessTokens.save(token, client.id, null, payload.scope, null,
          function(err) {
            done(err, err ? null : token);
          });
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
    server.authorization(function(clientID, redirectURI, done) {
      debug('Verifying client %s %s', clientID, redirectURI);
      models.clients.findByClientId(clientID, function(err, client) {
        if (err || !client) {
          return done(err);
        }
        debug('Client found: %s', clientInfo(client));
        var redirectURIs = [];
        if (typeof client.redirectURI === 'string') {
          redirectURIs.push(client.redirectURI);
        }
        if (Array.isArray(client.redirectURIs)) {
          redirectURIs = redirectURIs.concat(client.redirectURIs);
        }
        debug('Checking redirect URIs %j', redirectURIs);
        if (redirectURIs.length === 0) {
          return done(null, client, redirectURI);
        } else {
          var matched = false;
          for (var i = 0, n = redirectURIs.length; i < n; i++) {
            if (redirectURI.indexOf(redirectURIs[i]) === 0) {
              matched = true;
              break;
            }
          }
          if (!matched) {
            err = new Error('Invalid redirectURI: ' + redirectURI);
            return done(err);
          }
          return done(null, client, redirectURI);
        }
      });
    }),
    login.ensureLoggedIn({ redirectTo: options.loginPage || '/login' }),
    function(req, res, next) {
      if (options.decisionPage) {
        var urlObj = {
          pathname: options.decisionPage,
          query: {
            transactionId: req.oauth2.transactionID,
            userId: req.oauth2.user.id,
            clientId: req.oauth2.client.id,
            scope: req.oauth2.req.scope,
            redirectURI: req.oauth2.redirectURI
          }
        };
        return res.redirect(url.format(urlObj));
      }
      res.render(options.decisionView || 'dialog',
        { transactionId: req.oauth2.transactionID,
          user: req.user, client: req.oauth2.client,
          scope: req.oauth2.req.scope,
          redirectURI: req.oauth2.redirectURI});
    },
    server.errorHandler({ mode: 'indirect' })
  ];

  /*
   user decision endpoint

   `decision` middleware processes a user's decision to allow or deny access
   requested by a client application.  Based on the grant type requested by the
   client, the above grant middleware configured above will be invoked to send
   a response.
   */
  handlers.decision = [
    login.ensureLoggedIn({ redirectTo: options.loginPage || '/login' }),
    server.decision()
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
      ['oauth2-client-password', 'oauth2-client-basic', 'oauth2-jwt-bearer'],
      { session: false }),
    server.token(),
    server.errorHandler()
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
      if (client.restApiKey !== clientSecret) {
        return done(null, false);
      }
      return done(null, client);
    });
  }

  // Strategies for oauth2 client-id/client-secret login
  // HTTP basic
  passport.use('oauth2-client-basic', new BasicStrategy(clientLogin));
  // Body
  passport.use('oauth2-client-password', new ClientPasswordStrategy(clientLogin));

  // The urlencoded middleware is required for oAuth 2.0 protocol endpoints
  var oauth2Paths = [
    options.authorizePath || '/oauth/authorize',
    options.tokenPath || '/oauth/token',
    options.decisionPath || '/oauth/authorize/decision',
    options.loginPath || '/login'
  ];
  app.middleware('parse', oauth2Paths, 
    app.loopback.urlencoded({extended: false}));
  app.middleware('parse', oauth2Paths, app.loopback.json({strict: false}));

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

  if (options.loginPath !== false) {
    /**
     * LocalStrategy
     *
     * This strategy is used to authenticate users based on a username and password.
     * Anytime a request is made to authorize an application, we must ensure that
     * a user is logged in before asking them to approve the request.
     */
    passport.use('oauth2-local', new LocalStrategy(userLogin));

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
    app.post(options.loginPath || '/login', passport.authenticate('oauth2-local',
      { successReturnToOrRedirect: '/',
        failureRedirect: options.loginPage || '/login' }));
  }

  app._oauth2Handlers = handlers;

  return handlers;
};
