/**
 * Module dependencies.
 */
var loopbackOAuth2 = require('./oauth2-loopback');
var exports = module.exports = loopbackOAuth2;

exports.oAuth2Provider = loopbackOAuth2; // Keep backward-compatibility
exports.oauth2orize = require('./oauth2orize');

/**
 * A factory function for middleware handler that obtains the `authentication`
 * handler configured by the OAuth2 component.
 */
exports.authenticate = function(options) {
  var router;
  return function oauth2AuthenticateHandler(req, res, next) {
    if (!router) {
      var app = req.app;
      var authenticate = app._oauth2Handlers && app._oauth2Handlers.authenticate;

      if (!authenticate) {
        return next(new Error(
          'The OAuth2 component was not configured for this application.'));
      }

      var handlers = authenticate(options);
      router = app.loopback.Router();
      for (var i = 0, n = handlers.length; i < n; i++) {
        router.use(handlers[i]);
      }
    }

    return router(req, res, next);
  };
}
