// Copyright IBM Corp. 2013,2014. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

'use strict';
var chai = require('chai');

chai.use(require('chai-connect-middleware'));
chai.use(require('chai-oauth2orize-grant'));

global.expect = chai.expect;
