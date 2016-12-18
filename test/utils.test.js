// Copyright IBM Corp. 2013. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

'use strict';
var utils = require('../lib/utils');

describe('shouldUse', function() {
  it('should preserve backward compatibility', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {};

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.true;
    });
  });

  it('should support passing a string to paths', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: '/api',
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.true;
    });
  });

  it('should support passing a regex to paths', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: /api/,
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.true;
    });
  });

  it('should support passing an array of strings to paths', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [/api/],
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.true;
    });
  });

  it('should support passing an array of objects to paths', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [{
        path: '/api',
      }],
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.true;
    });
  });

  it('should support passing a string to exclude', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [{
        path: '/api',
        exclude: 'users',
      }],
    };
    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.false;
    });
  });

  it('should support passing a regex to exclude', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [{
        path: '/api',
        exclude: /users/,
      }],
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.false;
    });
  });

  it('should support passing an object to exclude', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [{
        path: '/api',
        exclude: {
          method: 'GET',
          path: 'users',
        },
      }],
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.false;
    });
  });

  it('should support passing a array of rules to exclude', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: [{
        path: '/api',
        exclude: [
          /app/,
          {
            method: 'GET',
            path: 'users',
          },
        ],
      }],
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.false;
    });
  });

  it('should exclude unrelated paths', function() {
    var req = {
      method: 'GET',
      _parsedUrl: {
        pathname: '/api/users',
      },
    };
    var options = {
      paths: '/app',
    };

    utils.shouldUse(req, options, function(testResult) {
      expect(testResult).to.be.false;
    });
  });
});
