// Copyright IBM Corp. 2013,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var chai = require('chai');

chai.use(require('chai-connect-middleware'));
chai.use(require('chai-oauth2orize-grant'));

global.expect = chai.expect;
