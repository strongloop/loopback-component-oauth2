// Copyright IBM Corp. 2015,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const crypto = require('crypto');
const utils = require('./utils');
const helpers = require('./oauth2-helper');
const jwt = require('jws');
const debug = require('debug')('loopback:oauth2');

const algorithms = {
  'hmac-sha-1': 'sha1',
  'hmac-sha-256': 'sha256',
};

module.exports = MACTokenGenerator;

function MACTokenGenerator(algorithm) {
  this.algorithm = algorithms[algorithm] || algorithm || 'sha1';
}

MACTokenGenerator.prototype.encode = function(key, text, encoding) {
  return crypto.createHmac(this.algorithm, key)
    .update(text).digest(encoding || 'base64');
};

MACTokenGenerator.prototype.generateToken = function(options) {
  const algorithm = this.algorithm === 'sha1' ? 'hmac-sha-1' : 'hmac-sha-256';
  const key = utils.uid(32);

  const payload = {
    iss: options.client.id, // issuer - client id
    sub: options.user && options.user.id, // subject
    aud: '/oauth/token', // audience
    exp: Date.now() + options.ttl * 1000, // expiration time
    iat: Date.now(), // issued at time
    scope: options.scope, // a list of oAuth 2.0 scopes
    mac_algorithm: algorithm,
    mac_key: key,
  };

  const secret = options.client.clientSecret || options.client.restApiKey;
  const jwtAlgorithm = options.jwtAlgorithm || 'HS256';

  // Sign the access token
  const token = helpers.generateJWT(payload, secret, jwtAlgorithm);
  const kid = crypto.createHash('sha1').update(token).digest('base64');

  return {
    id: token,
    token_type: 'mac',
    kid: kid,
    mac_algorithm: algorithm,
    mac_key: key,
  };
};

MACTokenGenerator.prototype.validate = function(req) {
  let authorizationHeader = req.get('authorization');
  if (!authorizationHeader) {
    return null;
  }
  // Parser the header
  /*
   Authorization: MAC access_token="h480djs93hd8",
   ts="1336363200",
   kid="dj83hs9s",
   mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
   */

  const params = {};
  let i;
  let n;
  if (authorizationHeader.indexOf('MAC ') === 0) {
    authorizationHeader = authorizationHeader.substring(4);
    const parts = authorizationHeader.split(/[,\s]+/).filter(Boolean);
    for (i = 0, n = parts.length; i < n; i++) {
      const part = parts[i];
      const index = part.indexOf('=');
      const kv = [];
      kv[0] = part.substring(0, index);
      kv[1] = part.substring(index + 1);
      let val = kv[1];
      if (val[0] === '"') {
        val = val.substring(1, val.length - 1);
      }
      params[kv[0]] = val;
    }
  } else {
    return null;
  }

  debug('MAC authorization: %s', authorizationHeader);

  const h = params.h || 'host';
  // var seqNr = params['seq-nr'];
  // var cb = params.cb;
  // var kid = params.kid;
  const ts = Number(params.ts) || 0;
  if ((Date.now() - ts) / 1000 > 300) {
    debug('Timestamp expired: %d', ts);
    return null;
  }
  const method = req.method.toUpperCase();
  const reqUri = req.originalUrl;
  const mac = params.mac;

  // Add header values
  const headers = [];
  const headerNames = h.split(/[,\s]+/).filter(Boolean);
  for (i = 0, n = headerNames.length; i < n; i++) {
    const header = req.get(headerNames[i]) || '';
    headers.push(header);
  }

  const accessToken = jwt.decode(params.access_token, {json: true});
  debug('Decoded access token: %j', accessToken);

  const text = [
    method + ' ' + reqUri + ' HTTP/' + req.httpVersion, ts,
  ].concat(headers).join('\n');

  const signature = this.encode(accessToken.payload.mac_key, text);

  debug('Input string: %s, key: %s, mac: %s',
    text, accessToken.payload.mac_key, signature);

  if (mac !== signature) {
    debug('MAC signature does not match');
    return null;
  }

  return params.access_token;
};
