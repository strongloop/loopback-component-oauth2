// Copyright IBM Corp. 2012,2013. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

'use strict';
exports.merge = require('utils-merge');
exports.uid = require('uid2');

exports.shouldUse = function(req, options, done) {
  if (!options.paths) return done(true); // Keep backward-compatibility
  if (req.headers.authorization) return done(true);

  if (options.paths.constructor !== Array) {
    options.paths = [options.paths];
  }

  var method = req.method.toLowerCase();
  var path = req._parsedUrl.pathname;
  var test = false;
  var exclude = false;

  for (var i = 0, n = options.paths.length; i < n; i++) {
    if ((options.paths[i].constructor === String || options.paths[i].constructor === RegExp) &&
      new RegExp('^' + options.paths[i], 'i').test(path)) {
      test = true;
      break;
    } else if (options.paths[i].constructor === Object &&
      new RegExp('^' + options.paths[i].path, 'i').test(path)) {
      test = true;
      if (typeof options.paths[i].exclude !== 'undefined') {
        exclude = options.paths[i].exclude;
      }
      break;
    }
  }

  if (exclude) {
    if (exclude.constructor !== Array) {
      exclude = [exclude];
    }
    for (var i = 0, n = exclude.length; i < n; i++) {
      if ((exclude[i].constructor === String || exclude[i].constructor === RegExp) &&
        new RegExp(exclude[i], 'i').test(path)) {
        test = false;
        break;
      } else if (exclude[i].constructor === Object) {
        if (exclude[i].method) {
          if (exclude[i].path &&
            exclude[i].method.toLowerCase() === method &&
            new RegExp(exclude[i].path, 'i').test(path)) {
            test = false;
            break;
          }
        } else {
          if (exclude[i].path &&
            new RegExp(exclude[i].path, 'i').test(path)) {
            test = false;
            break;
          }
        }
      }
    }
  }

  return done(test);
};
