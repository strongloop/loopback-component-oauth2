// Copyright IBM Corp. 2013,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const Server = require('../lib/server');
const expect = require('chai').expect;

describe('Server', function() {
  describe('#serializeClient', function() {
    describe('no serializers', function() {
      const server = new Server();

      describe('serializing', function() {
        let obj, err;

        before(function(done) {
          server.serializeClient({id: '1', name: 'Foo'}, function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal(
            'Failed to serialize client. Register serialization function using serializeClient().'
          );
        });
      });
    });

    describe('one serializer', function() {
      const server = new Server();
      server.serializeClient(function(client, done) {
        done(null, client.id);
      });

      describe('serializing', function() {
        let obj, err;

        before(function(done) {
          server.serializeClient({id: '1', name: 'Foo'}, function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should serialize', function() {
          expect(obj).to.equal('1');
        });
      });
    });

    describe('multiple serializers', function() {
      const server = new Server();
      server.serializeClient(function(client, done) {
        done('pass');
      });
      server.serializeClient(function(client, done) {
        done(null, '#2');
      });
      server.serializeClient(function(client, done) {
        done(null, '#3');
      });

      describe('serializing', function() {
        let obj, err;

        before(function(done) {
          server.serializeClient({id: '1', name: 'Foo'}, function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should serialize', function() {
          expect(obj).to.equal('#2');
        });
      });
    });

    describe('serializer that encounters an error', function() {
      const server = new Server();
      server.serializeClient(function(client, done) {
        return done(new Error('something went wrong'));
      });

      describe('serializing', function() {
        let obj, err;

        before(function(done) {
          server.serializeClient({id: '1', name: 'Foo'}, function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('something went wrong');
        });
      });
    });

    describe('serializer that throws an exception', function() {
      const server = new Server();
      server.serializeClient(function(client, done) {
        throw new Error('something was thrown');
      });

      describe('serializing', function() {
        let obj, err;

        before(function(done) {
          server.serializeClient({id: '1', name: 'Foo'}, function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('something was thrown');
        });
      });
    });
  }); // #serializeClient

  describe('#deserializeClient', function() {
    describe('no deserializers', function() {
      const server = new Server();

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal(
            'Failed to deserialize client. Register deserialization function using deserializeClient().'
          );
        });
      });
    });

    describe('one deserializer', function() {
      const server = new Server();
      server.deserializeClient(function(id, done) {
        done(null, {id: id});
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should deserialize', function() {
          expect(obj.id).to.equal('1');
        });
      });
    });

    describe('multiple deserializers', function() {
      const server = new Server();
      server.deserializeClient(function(id, done) {
        done('pass');
      });
      server.deserializeClient(function(id, done) {
        done(null, {id: '#2'});
      });
      server.deserializeClient(function(id, done) {
        done(null, {id: '#3'});
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should deserialize', function() {
          expect(obj.id).to.equal('#2');
        });
      });
    });

    describe('one deserializer to null', function() {
      const server = new Server();
      server.deserializeClient(function(id, done) {
        done(null, null);
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('one deserializer to false', function() {
      const server = new Server();
      server.deserializeClient(function(id, done) {
        done(null, false);
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('multiple deserializers to null', function() {
      const server = new Server();
      server.deserializeClient(function(obj, done) {
        done('pass');
      });
      server.deserializeClient(function(id, done) {
        done(null, null);
      });
      server.deserializeClient(function(obj, done) {
        done(null, {id: '#3'});
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('multiple deserializers to false', function() {
      const server = new Server();
      server.deserializeClient(function(obj, done) {
        done('pass');
      });
      server.deserializeClient(function(id, done) {
        done(null, false);
      });
      server.deserializeClient(function(obj, done) {
        done(null, {id: '#3'});
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should not error', function() {
          expect(err).to.be.null;
        });

        it('should invalidate client', function() {
          expect(obj).to.be.false;
        });
      });
    });

    describe('deserializer that encounters an error', function() {
      const server = new Server();
      server.deserializeClient(function(obj, done) {
        return done(new Error('something went wrong'));
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('something went wrong');
        });
      });
    });

    describe('deserializer that throws an exception', function() {
      const server = new Server();
      server.deserializeClient(function(obj, done) {
        throw new Error('something was thrown');
      });

      describe('deserializing', function() {
        let obj, err;

        before(function(done) {
          server.deserializeClient('1', function(e, o) {
            err = e;
            obj = o;
            return done();
          });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceOf(Error);
          expect(err.message).to.equal('something was thrown');
        });
      });
    });
  }); // #deserializeClient
});
