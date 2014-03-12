/**
 * Module dependencies.
 */
var oauth2Provider = require('./index')
  , passport = require('passport')
  , login = require('connect-ensure-login')
  , models = require('./models/index')
  , utils = require('./utils')
  , LocalStrategy = require('passport-local').Strategy
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
  , BearerStrategy = require('passport-http-bearer').Strategy
  , db = require('./models');


// create OAuth 2.0 server
var server = oauth2Provider.createServer();

// Register serialialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated.  To complete the transaction, the
// user must authenticate and approve the authorization request.  Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session.  Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient(function (client, done) {
  return done(null, client.id);
});

server.deserializeClient(function (id, done) {
  // console.log("Id: " + id);
  models.clients.findByClientId(id, function (err, client) {
    if (err) {
      return done(err);
    }
    return done(null, client);
  });
});

// Register supported grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

// Grant authorization codes.  The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

server.grant(oauth2Provider.grant.code(function (client, redirectURI, user, scope, ares, done) {
  var code = utils.uid(32);

  models.authorizationCodes.save(code, client.id, redirectURI, user.id, scope, function (err) {
    if (err) {
      return done(err);
    }
    done(null, code);
  });
}));

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

server.exchange(oauth2Provider.exchange.code(function (client, code, redirectURI, done) {
  models.authorizationCodes.findByCode(code, function (err, authCode) {
    if (err) {
      return done(err);
    }
    // The client id can be a number instead of string
    if (client.id != authCode.clientId) {
      return done(null, false);
    }
    if (redirectURI !== authCode.redirectURI) {
      return done(null, false);
    }

    var token = utils.uid(32);
    models.accessTokens.save(token, authCode.clientId, authCode.resourceOwner, authCode.scopes, function (err) {

      if (err) {
        return done(err);
      }
      done(null, token);
    });
  });
}));

server.exchange(oauth2Provider.exchange.password(function (client, username, password, scope, done) {
  models.users.findByUsername(username, function (err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      return done(null, false);
    }
    user.hasPassword(password, function(err, matched) {
      if(err || !matched) {
        return done(err, false);
      }
      var token = utils.uid(32);
      models.accessTokens.save(token, client.id, user.id, scope, function (err) {
        if (err) {
          return done(err);
        }
        done(null, token);
      });
    });
  });
}));

server.exchange(oauth2Provider.exchange.clientCredentials(function (client, scope, done) {
  var token = utils.uid(32);
  models.accessTokens.save(token, client.clientId, null, scope, function (err) {
    if (err) {
      return done(err);
    }
    done(null, token);
  });
}));

server.exchange(oauth2Provider.exchange.refreshToken(function (client, refreshToken, scope, done) {
  var token = utils.uid(32);
  models.accessTokens.save(token, client.clientId, null, scope, function (err) {
    if (err) {
      return done(err);
    }
    done(null, token);
  });
}));

server.grant(oauth2Provider.grant.token(function (client, user, scope, ares, done) {
  var token = utils.uid(32);
  models.accessTokens.save(token, client.id, user.id, scope, function (err) {
    if (err) {
      return done(err);
    }
    done(null, token);
  });
}));

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

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function (clientID, redirectURI, done) {
    models.clients.findByClientId(clientID, function (err, client) {
      if (err) {
        return done(err);
      }
      // WARNING: For security purposes, it is highly advisable to check that
      //          redirectURI provided by the client matches one registered with
      //          the server.  For simplicity, this example does not.  You have
      //          been warned.
      return done(null, client, redirectURI);
    });
  }),
  function (req, res) {
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

exports.decision = [
  login.ensureLoggedIn(),
  server.decision()
];

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['oauth2-client-password', 'basic'], { session: false }),
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
passport.use(new LocalStrategy(
  function(username, password, done) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      user.hasPassword(password, function(err, matched) {
        done(err, matched? user: null);
      });
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.users.find(id, function (err, user) {
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
passport.use(new BasicStrategy(
  function(username, password, done) {
    db.clients.findByClientId(username, function(err, client) {
      if (err) { return done(err); }
      if (!client) { return done(null, false); }
      if (client.restApiKey !== password) { return done(null, false); }
      return done(null, client);
    });
  }
));

passport.use(new ClientPasswordStrategy(
  function(clientId, clientSecret, done) {
    db.clients.findByClientId(clientId, function(err, client) {
      if (err) { return done(err); }
      if (!client) { return done(null, false); }
      if (client.restApiKey !== clientSecret) { return done(null, false); }
      return done(null, client);
    });
  }
));

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
    db.accessTokens.find(accessToken, function(err, token) {
      if (err) { return done(err); }
      if (!token) { return done(null, false); }

      db.users.find(token.resourceOwner, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        // to keep this example simple, restricted scopes are not implemented,
        // and this is just for illustrative purposes
        var info = { scope: token.scopes };
        done(null, user, info);
      });
    });
  }
));
