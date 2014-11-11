/**
 * Module dependencies.
 */
var loopbackOAuth2 = require('./oauth2-loopback');
var exports = module.exports = loopbackOAuth2;

exports.oAuth2Provider = loopbackOAuth2; // Keep backward-compatibility
exports.oauth2orize = require('./oauth2orize');