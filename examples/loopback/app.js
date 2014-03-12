/**
 * Module dependencies.
 */
var loopback = require('loopback')
  , passport = require('passport')
  , http = require('http')
  , https = require('https')
  , path = require('path')
  , site = require('./site')
  , user = require('./user')
  , sslCert = require('./private/ssl_cert');


var options = {
  key: sslCert.privateKey,
  cert: sslCert.certificate
};

// Express configuration
  
var app = loopback();

/*
 * 1. Configure LoopBack models and datasources
 *
 * Read more at http://apidocs.strongloop.com/loopback#appbootoptions
 */

app.boot(__dirname);

var oauth2 = require('../../lib/oauth2-provider');

loopback.autoAttach();

app.set('view engine', 'ejs');
app.use(loopback.logger());

app.use(loopback.cookieParser());
app.use(loopback.bodyParser());
app.use(loopback.session({ secret: 'keyboard cat' }));

app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(loopback.errorHandler({ dumpExceptions: true, showStack: true }));

app.use('/protected', function(req, res, next) {
  passport.authenticate('bearer', 
                        {session: false, scope: 's1'})(req, res, next); }); 

app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.get('/oauth/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);

app.get('/api/userinfo', user.info);

app.get('/callback', site.callbackPage);

app.set('views', __dirname + '/views');
app.use(loopback.static(path.join(__dirname, 'public')));

app.models.user.create({username: 'bob',
  password: 'secret',
  email: 'foo@bar.com'}, function(err, user) {

    // Hack to set the app id to a fixed value so that we don't have to change
    // the client settings
    app.models.application.beforeSave = function (next) {
      this.id = 123;
      this.restApiKey = 'secret';
      next();
    };
  app.models.application.register(
      user.id,
      'demo-app',
      {
      },
      function (err, demo) {
        if (err) {
          console.error(err);
        } else {
          console.log(demo.id, demo.restApiKey);
        }
      }
    );

  });

// app.listen(3000);
http.createServer(app).listen(9080);
console.log("http://localhost:9080");
https.createServer(options, app).listen(9443);
console.log("https://localhost:9443");
