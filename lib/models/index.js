/**
 * Create oAuth 2.0 metadata models
 * @param loopback
 * @param dataSource
 * @returns {{}}
 */
module.exports = function (loopback, dataSource) {
  var models = {};
  models.users = require('./users')(loopback);
  models.clients = require('./clients')(loopback);
  var oauth2 = require('./oauth2')(dataSource);
  models.accessTokens = require('./access-token')(oauth2);
  models.authorizationCodes = require('./authorization-code')(oauth2);
  return models;
};

