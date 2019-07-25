// Copyright IBM Corp. 2013,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const Server = require('../lib/server');
const expect = require('chai').expect;

describe('Server', function() {
  describe('registering a grant module', function() {
    const server = new Server();
    const mod = {};
    mod.name = 'foo';
    mod.request = function(req) {};
    mod.response = function(txn, res, next) {};
    server.grant(mod);

    it('should have one request parser', function() {
      expect(server._reqParsers).to.have.length(1);
      const parser = server._reqParsers[0];
      expect(parser.type.toString()).to.equal('foo');
      expect(parser.handle).to.be.a('function');
      expect(parser.handle).to.have.length(1);
    });

    it('should have one response handler', function() {
      expect(server._resHandlers).to.have.length(1);
      const handler = server._resHandlers[0];
      expect(handler.type.toString()).to.equal('foo');
      expect(handler.handle).to.be.a('function');
      expect(handler.handle).to.have.length(3);
    });
  });

  describe('registering a grant module by type', function() {
    const server = new Server();
    const mod = {};
    mod.name = 'foo';
    mod.request = function(req) {};
    mod.response = function(txn, res, next) {};
    server.grant('bar', mod);

    it('should have one request parser', function() {
      expect(server._reqParsers).to.have.length(1);
      const parser = server._reqParsers[0];
      expect(parser.type.toString()).to.equal('bar');
      expect(parser.handle).to.be.a('function');
      expect(parser.handle).to.have.length(1);
    });

    it('should have one response handler', function() {
      expect(server._resHandlers).to.have.length(1);
      const handler = server._resHandlers[0];
      expect(handler.type.toString()).to.equal('bar');
      expect(handler.handle).to.be.a('function');
      expect(handler.handle).to.have.length(3);
    });
  });

  describe('registering a grant parsing function by type', function() {
    const server = new Server();
    const mod = {};
    server.grant('foo', function(req) {});

    it('should have one request parser', function() {
      expect(server._reqParsers).to.have.length(1);
      const parser = server._reqParsers[0];
      expect(parser.type.toString()).to.equal('foo');
      expect(parser.handle).to.be.a('function');
      expect(parser.handle).to.have.length(1);
    });

    it('should not have any response handlers', function() {
      expect(server._resHandlers).to.have.length(0);
    });
  });

  describe('registering a grant parsing function by type and phase', function() {
    const server = new Server();
    const mod = {};
    server.grant('foo', 'request', function(req) {});

    it('should have one request parser', function() {
      expect(server._reqParsers).to.have.length(1);
      const parser = server._reqParsers[0];
      expect(parser.type.toString()).to.equal('foo');
      expect(parser.handle).to.be.a('function');
      expect(parser.handle).to.have.length(1);
    });

    it('should not have any response handlers', function() {
      expect(server._resHandlers).to.have.length(0);
    });
  });

  describe('registering a wildcard grant parsing function', function() {
    const server = new Server();
    const mod = {};
    server.grant('*', function(req) {});

    it('should have one request parser', function() {
      expect(server._reqParsers).to.have.length(1);
      const parser = server._reqParsers[0];
      expect(parser.type).to.be.null;
      expect(parser.handle).to.be.a('function');
      expect(parser.handle).to.have.length(1);
    });

    it('should not have any response handlers', function() {
      expect(server._resHandlers).to.have.length(0);
    });
  });

  describe('registering a grant responding function by type and phase', function() {
    const server = new Server();
    const mod = {};
    server.grant('foo', 'response', function(txn, res, next) {});

    it('should not have any request parsers', function() {
      expect(server._reqParsers).to.have.length(0);
    });

    it('should have one response handler', function() {
      expect(server._resHandlers).to.have.length(1);
      const handler = server._resHandlers[0];
      expect(handler.type.toString()).to.equal('foo');
      expect(handler.handle).to.be.a('function');
      expect(handler.handle).to.have.length(3);
    });
  });

  describe('registering a wildcard grant responding function', function() {
    const server = new Server();
    const mod = {};
    server.grant('*', 'response', function(txn, res, next) {});

    it('should not have any request parsers', function() {
      expect(server._reqParsers).to.have.length(0);
    });

    it('should have one response handler', function() {
      expect(server._resHandlers).to.have.length(1);
      const handler = server._resHandlers[0];
      expect(handler.type).to.be.null;
      expect(handler.handle).to.be.a('function');
      expect(handler.handle).to.have.length(3);
    });
  });
});
