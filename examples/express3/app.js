/**
 * Module dependencies.
 */
var express = require('express')
  , passport = require('passport')
  , site = require('./site')
  , oauth2 = require('./oauth2')
  , user = require('./user')
  , util = require('util')
  , http = require('http')
  , https = require('https') 
  , sslCert = require('./private/ssl_cert')


var options = {
  key: sslCert.privateKey,
  cert: sslCert.certificate
};

// Express configuration
  
var app = express();

app.set('view engine', 'ejs');
app.use(express.logger());
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.session({ secret: 'keyboard cat' }));
/*
app.use(function(req, res, next) {
  console.log('-- session --');
  console.dir(req.session);
  //console.log(util.inspect(req.session, true, 3));
  console.log('-------------');
  next()
});
*/
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));

// Passport configuration

require('./auth');


app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);

app.get('/api/userinfo', user.info);

app.get('/callback', site.callbackPage);

// app.listen(3000);
http.createServer(app).listen(9080);
https.createServer(options, app).listen(9443);
