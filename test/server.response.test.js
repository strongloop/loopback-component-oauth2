// Copyright IBM Corp. 2013,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const Server = require('../lib/server');
const expect = require('chai').expect;

describe('Server', function() {
  describe('handling authorization response with one supported type', function() {
    const server = new Server();
    server.grant('foo', 'response', function(txn, res, next) {
      if (txn.req.scope != 'read') { return next(new Error('something is wrong')); }
      res.end('abc');
    });

    describe('response to supported type', function() {
      let result, err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};
        res.end = function(data) {
          result = data;
          done();
        };

        server._respond(txn, res, function(e) {
          done(new Error('should not be called'));
        });
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(result).to.equal('abc');
      });
    });

    describe('response to unsupported type', function() {
      let result, err;

      before(function(done) {
        const txn = {req: {type: 'unsupported'}};
        const res = {};
        res.end = function(data) {
          done(new Error('should not be called'));
        };

        server._respond(txn, res, function(e) {
          err = e;
          done();
        });
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });
    });
  });

  describe('handling authorization response with one wildcard responder', function() {
    const server = new Server();
    server.grant('*', 'response', function(txn, res, next) {
      res.end('abc');
    });

    describe('response to a type', function() {
      let result, err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};
        res.end = function(data) {
          result = data;
          done();
        };

        server._respond(txn, res, function(e) {
          done(new Error('should not be called'));
        });
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(result).to.equal('abc');
      });
    });
  });

  describe('handling authorization response with one wildcard responder and one supported type', function() {
    const server = new Server();
    server.grant('*', 'response', function(txn, res, next) {
      res.star = true;
      next();
    });
    server.grant('foo', 'response', function(txn, res, next) {
      if (!res.star) { return next(new Error('something is wrong')); }
      res.end('abc');
    });

    describe('response to a type', function() {
      let response, result, err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};
        res.end = function(data) {
          result = data;
          done();
        };

        response = res;
        server._respond(txn, res, function(e) {
          done(new Error('should not be called'));
        });
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });

      it('should send response', function() {
        expect(result).to.equal('abc');
      });
    });
  });

  describe('handling authorization response with responder that encounters an error', function() {
    const server = new Server();
    server.grant('foo', 'response', function(txn, res, next) {
      next(new Error('something went wrong'));
    });

    describe('response to a type', function() {
      let result, err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};
        res.end = function(data) {
          done(new Error('should not be called'));
        };

        server._respond(txn, res, function(e) {
          err = e;
          done();
        });
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });

  describe('handling authorization response with responder that throws an exception', function() {
    const server = new Server();
    server.grant('foo', 'response', function(txn, res, next) {
      throw new Error('something was thrown');
    });

    describe('response to a type', function() {
      let result, err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};
        res.end = function(data) {
          done(new Error('should not be called'));
        };

        server._respond(txn, res, function(e) {
          err = e;
          done();
        });
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something was thrown');
      });
    });
  });

  describe('handling authorization response with no supported types', function() {
    const server = new Server();

    describe('response', function() {
      let err;

      before(function(done) {
        const txn = {req: {type: 'foo', scope: 'read'}};
        const res = {};

        server._respond(txn, res, function(e) {
          err = e;
          done();
        });
      });

      it('should not error', function() {
        expect(err).to.be.undefined;
      });
    });
  });
});
