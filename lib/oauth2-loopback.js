/**
 * Module dependencies.
 */
var oauth2Provider = require('./index')
  , utils = require('./utils')
  , modelBuilder = require('./models/index')
  , debug = require('debug')('loopback:oauth2')
  , passport = require('passport')
  , login = require('connect-ensure-login')
  , LocalStrategy = require('passport-local').Strategy
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
  , BearerStrategy = require('passport-http-bearer').Strategy
  , ClientJWTBearerStrategy = require('passport-oauth2-jwt-bearer').Strategy;

module.exports = function(app, options) {
  options = options || {};
  var models = modelBuilder(app, options);

  var generateToken = options.generateToken || function(options) {
    return utils.uid(32);
  }

  // create OAuth 2.0 server
  var server = oauth2Provider.createServer();

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
  server.serializeClient(function(client, done) {
    debug('serializeClient: %s', clientInfo(client));
    return done(null, client.id);
  });

  server.deserializeClient(function(id, done) {
    debug('deserializeClient: %s', id);
    models.clients.findByClientId(id, done);
  });

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
  server.grant(oauth2Provider.grant.code(
    function(client, redirectURI, user, scope, ares, done) {
      var code = generateToken();
      debug('Generating authorization code: %s %s %s %s %s',
        code, clientInfo(client), redirectURI, userInfo(user), scope);
      models.authorizationCodes.save(code, client.id, redirectURI, user.id, scope,
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
        // The client id can be a number instead of string
        if (client.id != authCode.clientId) {
          return done(null, false);
        }
        if (redirectURI !== authCode.redirectURI) {
          return done(null, false);
        }

        var token = generateToken();

        debug('Generating access token: %s %s %s',
          token, clientInfo(client), redirectURI);

        models.accessTokens.save(token, authCode.clientId,
          authCode.resourceOwner, authCode.scopes,
          function(err) {

            if (err) {
              return done(err);
            }
            done(null, token);
          });
      });
    }));

  function userLogin(username, password, done) {
    models.users.findByUsername(username, function(err, user) {
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
  server.exchange(oauth2Provider.exchange.password(
    function(client, username, password, scope, done) {
      debug('Verifying username/password: %s %s %s',
        clientInfo(client), username, scope);

      userLogin(username, password, function(err, user) {
        if (err || !user) {
          return done(err, null);
        }
        var token = generateToken();
        debug('Generating access token: %s %s %s %s',
          token, clientInfo(client), username, scope);

        models.accessTokens.save(token, client.id, user.id, scope,
          function(err) {
            done(err, err ? null : token);
          });
      });
    }));

  /*
   * Client credentials flow
   */
  server.exchange(oauth2Provider.exchange.clientCredentials(
    function(client, scope, done) {
      var token = generateToken();
      debug('Generating access token: %s %s %s',
        token, clientInfo(client), scope);

      models.accessTokens.save(token, client.clientId, null, scope,
        function(err) {
          done(err, err ? null : token);
        });
    }));

  /*
   * Refresh token flow
   */
  server.exchange(oauth2Provider.exchange.refreshToken(
    function(client, refreshToken, scope, done) {
      var token = generateToken();
      debug('Generating access token: %s %s %s %j',
        token, clientInfo(client), scope, refreshToken);

      models.accessTokens.save(token, client.clientId, null, scope,
        function(err) {
          done(err, err ? null : token);
        });
    }));

  server.grant(oauth2Provider.grant.token(
    function(client, user, scope, ares, done) {
      var token = generateToken();
      debug('Generating access token: %s %s %s %s',
        token, clientInfo(client), userInfo(user), scope);

      models.accessTokens.save(token, client.id, user.id, scope,
        function(err) {
          done(err, err ? null : token);
        });
    }));

  /*
   var jwtBearer = require('oauth2orize-jwt-bearer').Exchange;

   server.exchange('urn:ietf:params:oauth:grant-type:jwt-bearer',
   jwtBearer(function (client, data, signature, done) {
   var crypto = require('crypto');
   var fs = require('fs');

   //load PEM format public key as string, should be clients public key
   var pub = fs.readFileSync('/path/to/public.pem').toString();
   var verifier = crypto.createVerify("RSA-SHA256");

   //verifier.update takes in a string of the data that is encrypted in the signature
   verifier.update(JSON.stringify(data));

   if (verifier.verify(pub, signature, 'base64')) {
   //base64url decode data
   var b64string = data;
   var buf = new Buffer(b64string, 'base64').toString('ascii');

   // TODO - verify client_id, scope and expiration are valid from the buf variable above

   var token = generateToken();
   models.accessTokens.save(token, client, null, scope, function (err, accessToken) {
   if (err) {
   return done(err);
   }
   done(null, accessToken);
   });
   }
   }));
   */

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view. 
  var handlers = {};
  handlers.authorization = [
    login.ensureLoggedIn(),
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
    function(req, res) {
      res.render('dialog', { transactionID: req.oauth2.transactionID,
        user: req.user, client: req.oauth2.client });
    }
  ];

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.
  handlers.decision = [
    login.ensureLoggedIn(),
    server.decision()
  ];

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

  handlers.token = [
    passport.authenticate(['oauth2-client-password', 'oauth2-client-basic'],
      { session: false }),
    server.token(),
    server.errorHandler()
  ];

  /**
   * LocalStrategy
   *
   * This strategy is used to authenticate users based on a username and password.
   * Anytime a request is made to authorize an application, we must ensure that
   * a user is logged in before asking them to approve the request.
   */
  passport.use(new LocalStrategy(userLogin));

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

  passport.use('oauth2-client-basic', new BasicStrategy(clientLogin));
  passport.use(new ClientPasswordStrategy(clientLogin));

  /**
   * BearerStrategy
   *
   * This strategy is used to authenticate users based on an access token (aka a
   * bearer token).  The user must have previously authorized a client
   * application, which is issued an access token to make requests on behalf of
   * the authorizing user.
   */
  passport.use(new BearerStrategy(
    function(accessToken, done) {
      debug('Verifying access token %s', accessToken);
      models.accessTokens.find(accessToken, function(err, token) {
        if (err || !token) {
          return done(err);
        }

        debug('Access token found: %j', accessToken);
        var userId = token.resourceOwner || token.userId;
        models.users.find(userId, function(err, user) {
          if (err || !user) {
            return done(err);
          }
          debug('User found: %s', userInfo(user));
          models.clients.find(token.clientId, function(err, app) {
            if (err || !app) {
              return done(err);
            }

            debug('Client found: %s', clientInfo(app));
            // to keep this example simple, restricted scopes are not implemented,
            // and this is just for illustrative purposes
            var authInfo = { accessToken: token, user: user, app: app };
            done(null, user, authInfo);
          });
        });
      });
    }
  ));

  passport.use(new ClientJWTBearerStrategy(
    function(claimSetIss, done) {
      models.clients.findByClientId(claimSetIss, function(err, client) {
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

  return handlers;
};
