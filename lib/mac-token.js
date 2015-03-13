var crypto = require("crypto");
var utils = require('./utils');
var helpers = require('./oauth2-helper');
var jwt = require('jws');

var algorithms = {
  "hmac-sha-1": 'sha1',
  "hmac-sha-256": 'sha256'
};

module.exports = MACTokenGenerator;

function MACTokenGenerator(algorithm) {
  this.algorithm = algorithms[algorithm] || algorithm || 'sha1';
}

MACTokenGenerator.prototype.encode = function(key, text, encoding) {
  return crypto.createHmac(this.algorithm)
    .update(text).digest(encoding || 'base64');
};

MACTokenGenerator.prototype.generateToken = function(options) {
  var algorithm = this.algorithm === 'sha1' ? 'hmac-sha-1' : 'hmac-sha-256';
  var key = utils.uid(32);

  var payload = {
    iss: options.client.id, // issuer - client id
    sub: options.user && options.user.id, // subject
    aud: '/oauth/token', // audience
    exp: Date.now() + options.ttl * 1000, // expiration time
    iat: Date.now(), // issued at time
    scope: options.scope, // a list of oAuth 2.0 scopes
    mac_algorithm: algorithm,
    mac_key: key
  };

  var secret = options.client.clientSecret || options.client.restApiKey;

  // Sign the access token
  var token = helpers.generateJWT(payload, secret, 'HS256');
  var kid = crypto.createHash('sha1').update(token).digest('base64');

  return {
    id: token,
    token_type: 'mac',
    kid: kid,
    mac_algorithm: algorithm,
    mac_key: key
  };
};

MACTokenGenerator.prototype.validate = function(req) {
  var authorizationHeader = req.get('authorization');
  if (!authorizationHeader) {
    return null;
  }
  // Parser the header
  /*
   Authorization: MAC access_token="h480djs93hd8",
   ts="1336363200",
   nonce="dj83hs9s",
   mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="
   */

  var params = {};
  var i;
  var n;
  if (authorizationHeader.indexOf('MAC ') === 0) {
    authorizationHeader = authorizationHeader.substring(4);
    var parts = authorizationHeader.split(/[,\s]+/).filter(Boolean);
    for (i = 0, n = parts.length; i < n; i++) {
      var part = parts[i];
      var kv = part.split('=');
      var val = kv[1];
      if (val[0] === '"') {
        val = val.substring(1, val.length - 1);
      }
      params[kv[0]] = val;
    }
  }

  var h = params.h || 'host';
  var seqNr = params['seq-nr'];
  var cb = params.cb;
  var kid = params.kid;
  var ts = params.ts;
  var nonce = params.nonce;
  var method = req.method.toUpperCase();
  var reqUri = req.originalUrl;
  var host = req.hostname.toLowerCase();
  var port = req.get('host').split(':')[1];
  if (port === undefined) {
    if (req.protocol === 'http') {
      port = 80;
    } else if (req.protocol === 'https') {
      port = 443;
    }
  }
  var ext = params.ext || '';
  var mac = params.mac;

  // Add header values
  var headers = [];
  var headerNames = h.split(/[,\s]+/).filter(Boolean);
  for (i = 0, n = headerNames.length; i < n; i++) {
    var header = req.get(headerNames[i]) || '';
    headers.push(header);
  }

  var text = [
    ts, nonce, method, reqUri, host, port, ext
  ].concat(headers).join('\n');

  var accessToken = jwt.decode(params.access_token, { json: true });

  var digest = this.encode(accessToken.payload.mac_key, text);
  if (mac !== digest) {
    return null;
  }

  return params.access_token;
}




