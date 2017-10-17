2017-10-17, Version 3.1.0
=========================

 * translation return for Q4 drop1 (tangyinb)

 * update globalize string (Diana Lau)

 * Add stalebot configuration (Kevin Delisle)

 * Create Issue and PR Templates (#73) (Sakib Hasan)

 * Add CODEOWNER file (Diana Lau)

 * update node version in travis (Diana Lau)

 * relicense under MIT and update copyright notices (Ryan Graham)

 * Replicate new issue_template from loopback (Siddhi Pai)

 * Replicate issue_template from loopback repo (Siddhi Pai)


2016-12-21, Version 3.0.0
=========================

 * Update paid support URL (Siddhi Pai)

 * Drop support for Node v0.10 and v0.12 (Siddhi Pai)

 * Start the development of the next major version (Siddhi Pai)

 * Update README doc links (Candy)


2016-10-07, Version 2.5.1
=========================

 * Update ja translation file (Candy)

 * Update translation files - round#2 (Candy)

 * Add translated files (gunjpan)

 * Update deps to loopback 3.0.0 RC (Miroslav Bajtoš)

 * Use loopback@3.0.0-alpha for running the tests. (Miroslav Bajtoš)


2016-09-09, Version 2.5.0
=========================

 * Fix deprecation warnings. (Jordan Pickwell)

 * Update dependencies (Loay)

 * Add eslint infrastructure (Loay)

 * Add globalization (Loay)

 * Update URLs in CONTRIBUTING.md (#36) (Ryan Graham)


2016-05-06, Version 2.4.1
=========================

 * update copyright notices and license (Ryan Graham)


2016-03-04, Version 2.4.0
=========================

 * Remove license check (Raymond Feng)


2016-02-19, Version 2.3.7
=========================

 * Remove sl-blip from dependencies (Miroslav Bajtoš)

 * Refer to licenses with a link (Sam Roberts)

 * Use strongloop conventions for licensing (Sam Roberts)


2015-08-31, Version 2.3.6
=========================

 * Add debug for authenticate options (Raymond Feng)

 * Fix OAuthScope options (Jonathan Woolsey)


2015-08-07, Version 2.3.5
=========================

 * Allow scopes to be string[] (Raymond Feng)


2015-07-17, Version 2.3.4
=========================

 * Fix the ref to route.methods (Raymond Feng)


2015-06-25, Version 2.3.3
=========================

 * Add an option to add http headers for app/user ids (Raymond Feng)


2015-06-23, Version 2.3.2
=========================

 * Pass req to checkAccessToken (Raymond Feng)


2015-06-18, Version 2.3.1
=========================

 * Allow checkAccessToken to a custom function (Raymond Feng)


2015-06-18, Version 2.3.0
=========================

 * Remove auth code after 1st use (Raymond Feng)

 * Allow options.scopes to be a custom function (Raymond Feng)


2015-06-16, Version 2.2.1
=========================

 * Allow options.userModel/applicationModel to be strings (Raymond Feng)


2015-06-12, Version 2.2.0
=========================

 * Tidy up the models to work with MySQL (Raymond Feng)


2015-06-11, Version 2.1.1
=========================

 * Allow models to be customized via options (Raymond Feng)


2015-06-11, Version 2.1.0
=========================

 * Fix typo (Raymond Feng)

 * Clean up oAuth2 client app attributes (Raymond Feng)

 * Add blip and license check (Raymond Feng)

 * Updated example link (Bryan Clark)


2015-05-28, Version 2.0.0
=========================

 * Change license to StrongLoop (Raymond Feng)


2015-05-17, Version 2.0.0-rc3
=============================

 * Fixed a minor bug where comparison of allowedScopes and tokenScopes is incorrect (Roy Klopper)


2015-05-16, Version 2.0.0-rc2
=============================

 * Fix token deletion (Raymond Feng)


2015-05-16, Version 2.0.0-rc1
=============================

 * Add revoke middleware (Raymond Feng)


2015-04-10, Version 2.0.0-beta9
===============================

 * Upgrade to jws 3.0.0 (Raymond Feng)


2015-03-20, Version 2.0.0-beta8
===============================

 * Fix up the model definitions (Raymond Feng)


2015-03-16, Version 2.0.0-beta7
===============================

 * Tidy up scope definition (Raymond Feng)


2015-03-13, Version 2.0.0-beta6
===============================

 * Tidy up token validations (Raymond Feng)

 * Tidy up token generation (Raymond Feng)

 * Allow jwt token type (Raymond Feng)

 * Initial mac token support (Raymond Feng)


2015-03-09, Version 2.0.0-beta5
===============================

 * Add tokenTypes (Raymond Feng)

 * Return anonymous user (Raymond Feng)

 * Tidy up application validation (Raymond Feng)

 * Add permission management and subject support for client credentials (Raymond Feng)

 * Pull in changes from upstream (Raymond Feng)


2015-01-30, Version 2.0.0-beta4
===============================

 * v2.0.0-beta4 (Raymond Feng)

 * Make sure bodyParser doesn't interfere with proxy (Raymond Feng)


2015-01-08, Version 2.0.0-beta3
===============================

 * v2.0.0-beta3 (Raymond Feng)

 * Fix the oAuth2 auth middleware for an array of handlers (Raymond Feng)


2015-01-07, Version 2.0.0-beta2
===============================

 * v2.0.0-beta2 (Miroslav Bajtoš)

 * Allow declarative config of OAuth2 component (Miroslav Bajtoš)

 * Fix bad CLA URL in CONTRIBUTING.md (Ryan Graham)


2014-12-17, Version 2.0.0-beta1
===============================

 * v2.0.0-beta1 (Raymond Feng)

 * Update deps (Raymond Feng)

 * Remove obsolete tests (Raymond Feng)

 * Tidy up missing user/app id error handling (Raymond Feng)

 * Tidy up validation of code and token (Raymond Feng)

 * Tidy up the endpoints based on tests from strong-gateway (Raymond Feng)

 * Add refresh token generation (Raymond Feng)

 * Export authenticate as a factory to middleware chain (Raymond Feng)

 * Fix the JWT parsing (Raymond Feng)

 * Add relations to oAuth models (Raymond Feng)

 * Allows email/username for login (Raymond Feng)

 * Use app.middleware to register handlers (Raymond Feng)

 * Refactor models into json definitions (Raymond Feng)

 * Link to docs - leave minimal README. (Rand McKinney)

 * Fix link to the gateway example (Raymond Feng)

 * Add CONTRIBUTING.md with contribution guidelines (Ryan Graham)

 * Fix the jwt verification (Raymond Feng)

 * Fix the findOne query objects (Raymond Feng)

 * Ident the code (Raymond Feng)

 * Update input to decision view/page (Raymond Feng)

 * Add decisionPage (Raymond Feng)

 * Tidy up and document options (Raymond Feng)

 * Align properties with existing accessToken/application models (Raymond Feng)

 * Set up access token into the req object (Raymond Feng)

 * Re-org the code so that protocol endpoints are decoupled from auth (Raymond Feng)

 * Make more steps configurable (Raymond Feng)

 * Move more configuration into the component (Raymond Feng)

 * Update docs (Raymond Feng)

 * Clean up bootstrap (Raymond Feng)

 * Rename to loopback-component-oauth2 (Raymond Feng)

 * Add more options (Raymond Feng)

 * Update README (Raymond Feng)

 * Fix token generation (Raymond Feng)

 * Support jwt client auth and authorization grant (Raymond Feng)

 * Enable JWT (Raymond Feng)

 * Add options to generateToken (Raymond Feng)

 * Add more debug statements (Raymond Feng)

 * Make sure authCode is found (Raymond Feng)

 * Tidy up oAuth2 integration (Raymond Feng)

 * Add more information to authInfo (Raymond Feng)

 * Tidy up models (Raymond Feng)

 * Move examples to loopback-example-oauth2 (Raymond Feng)

 * Upgrade deps (Raymond Feng)

 * Upgrade to LB 2.0 (Raymond Feng)

 * Add admin UI (Raymond Feng)

 * Fix the ejs templates (Raymond Feng)

 * Fix the model calls (Raymond Feng)

 * Rename express3 to loopback (Raymond Feng)

 * Allow the oauth models to be auto attached (Raymond Feng)

 * Try to bring up the e2e example (Raymond Feng)

 * Add NOTICE file (Raymond Feng)

 * Update license to dual Artistic-2.0/StrongLoop (Raymond Feng)

 * Code style clean up (Raymond Feng)

 * Fix typo in doc-block (Thierry Marianne)

 * Bring up the bearer example (Raymond Feng)

 * Start to add loopback integration (Raymond Feng)

 * Add scope param (Raymond Feng)

 * Fix merge problems (Raymond Feng)

 * Update package.json (Raymond Feng)

 * Relocate the repo (Raymond Feng)

 * Add the scope for token saving (Raymond Feng)

 * Start to enable http-proxy (Raymond Feng)

 * Protect the "/protected" with oAuth bearer token (Raymond Feng)

 * Add more info to the README.md (Raymond Feng)

 * Bring up more grant types (Raymond Feng)

 * Fix the field name (Raymond Feng)

 * Format the code using Eclipse (Raymond Feng)

 * More refactoring and UI enhancements (Raymond Feng)

 * Upgrade to express 3.x and enable SSL (Raymond Feng)

 * Move the initialization of oauth users/clients to index.js (Raymond Feng)

 * Fix the token grant reg (Raymond Feng)

 * Use MongoDB as the store for oAuth 2.0 metadata (Raymond Feng)

 * Fix quality badge. (Jared Hanson)

 * Delint tests. (Jared Hanson)

 * Add tips badge to README. (Jared Hanson)

 * Add quality badge to README. (Jared Hanson)

 * Remove unused support files. (Jared Hanson)

 * Update support files. (Jared Hanson)

 * Bump version to 1.0.1. (Jared Hanson)

 * Update chai plugins and test cases. (Jared Hanson)

 * Disable Node 0.6 on Travis CI. (Jared Hanson)

 * added a README (AJ ONeal)

 * Update server.test.js (noamcb)

 * Update server.js (noamcb)

 * Bump version to 1.0.0. (Jared Hanson)

 * Update README. (Jared Hanson)

 * Fragment encode error responses for implicit grant. (Jared Hanson)

 * Implement contains and containsAny functions for UnorderedList. (Jared Hanson)

 * Use dependenceis for utils. (Jared Hanson)

 * Delint Server. (Jared Hanson)

 * Delint errors. (Jared Hanson)

 * Delint exchanges. (Jared Hanson)

 * Delint grants. (Jared Hanson)

 * Delint middleware. (Jared Hanson)

 * Test case for immediate callback with scope. (Jared Hanson)

 * Test cases for immediate mode callback error handling. (Jared Hanson)

 * Test cases for immediate mode callback. (Jared Hanson)

 * Capitalize Bearer, as that seems to be the emerging convention. (Jared Hanson)

 * Add test cases for TokenError. (Jared Hanson)

 * Use token error in exchanges. (Jared Hanson)

 * Use token error in token middleware. (Jared Hanson)

 * Export TokenError. (Jared Hanson)

 * Use token error in authorization code exchange. (Jared Hanson)

 * Add TokenError class. (Jared Hanson)

 * Refactor immediate mode callback for style and extensibility. (Jared Hanson)

 * Define sources in Makefile. (Jared Hanson)

 * Implement support for access token and params for other exchanges. (Jared Hanson)

 * Format documentation. (Jared Hanson)

 * Test case for access token and params in client credentials. (Jared Hanson)

 * Fix merge conflicts. (Jared Hanson)

 * Expand test coverage of Server. (Jared Hanson)

 * Expand test coverage of UnorderedList. (Jared Hanson)

 * Add test cases for ForbiddenError. (Jared Hanson)

 * Remove vows tests for Server. (Jared Hanson)

 * Clean up test cases for serialization. (Jared Hanson)

 * Clean up test cases for exchange. (Jared Hanson)

 * Clean up test cases for response handling. (Jared Hanson)

 * Clean up test cases for request parsing. (Jared Hanson)

 * Rename _exchangers ivar to _exchanges. (Jared Hanson)

 * Remove vows tests for refresh token exchange. (Jared Hanson)

 * Catch exceptions thrown from issue callback in refresh token exchange. (Jared Hanson)

 * Remove vows tests for password exchange. (Jared Hanson)

 * Catch exceptions thrown from issue callback in password exchange. (Jared Hanson)

 * Remove vows tests for client credentials exchange. (Jared Hanson)

 * Catch exceptions thrown from issue callback in client credentials exchange. (Jared Hanson)

 * Remove vows tests for authorization code exchange. (Jared Hanson)

 * Catch exceptions thrown from issue callback in authorization code exchange. (Jared Hanson)

 * Remove vows test for package exports. (Jared Hanson)

 * Remove vows tests for UnorderedList. (Jared Hanson)

 * Remove vows tests for token middleware. (Jared Hanson)

 * Remove vows tests for errorHandler middleware. (Jared Hanson)

 * Remove vows tests for decision middleware. (Jared Hanson)

 * Clarify errors. (Jared Hanson)

 * Clean up decision middleware test cases. (Jared Hanson)

 * Remove vows tests for transactionLoader middleware. (Jared Hanson)

 * Clean up transactionLoader middleware tests. (Jared Hanson)

 * Remove vows tests for authorization middleware. (Jared Hanson)

 * Catch exceptions thrown from validate callback. (Jared Hanson)

 * Clean up authorization middleware tests. (Jared Hanson)

 * Remove vows tests for token grant. (Jared Hanson)

 * Clean up token grant tests. (Jared Hanson)

 * Remove vows tests for code grant. (Jared Hanson)

 * Clean up code grant tests. (Jared Hanson)

 * Remove vows dependency. (Jared Hanson)

 * Port deserialize client test cases to Mocha. (Jared Hanson)

 * Port serialize client test cases to Mocha. (Jared Hanson)

 * Port exchange test cases to Mocha. (Jared Hanson)

 * Port response test cases to Mocha. (Jared Hanson)

 * More request test case porting. (Jared Hanson)

 * Reorganize tests. (Jared Hanson)

 * More test case porting. (Jared Hanson)

 * Port request parsing test cases to Mocha. (Jared Hanson)

 * Port grant registration test cases to Mocha. (Jared Hanson)

 * Port initial Server test case to Mocha. (Jared Hanson)

 * Clean up package tests. (Jared Hanson)

 * Port UnorderedList tests to Mocha. (Jared Hanson)

 * Add test case for BadRequestError. (Jared Hanson)

 * Add test case for AuthorizationError. (Jared Hanson)

 * Port token grant test cases to Mocha. (Jared Hanson)

 * Port token grant test case to Mocha. (Jared Hanson)

 * Improve test error messages. (Jared Hanson)

 * Port code grant handling test cases to Mocha. (Jared Hanson)

 * Port code grant parsing test cases to Mocha. (Jared Hanson)

 * Initial port of code grant test cases to Mocha. (Jared Hanson)

 * Port refreshToken exchange test cases to Mocha. (Jared Hanson)

 * Port password exchange test cases to Mocha. (Jared Hanson)

 * Port clientCredentials exchange test cases to Mocha. (Jared Hanson)

 * Port authorizationCode exchange test cases to Mocha. (Jared Hanson)

 * Port token test cases to Mocha. (Jared Hanson)

 * Port initial test cases for token middleware to Mocha. (Jared Hanson)

 * Clarify error message. (Jared Hanson)

 * Port authorization test cases to Mocha. (Jared Hanson)

 * Initial test cases for authorization middleware. (Jared Hanson)

 * Disable legacy tests. (Jared Hanson)

 * More test case porting for decision middleware. (Jared Hanson)

 * Add test case for decision middleware with parsing function. (Jared Hanson)

 * Additional test coverage for decision middleware. (Jared Hanson)

 * Initial test case for decision middleware. (Jared Hanson)

 * Improve error message. (Jared Hanson)

 * Additional test coverage for transactionLoader. (Jared Hanson)

 * Initial test case for transactionLoader. (Jared Hanson)

 * Test case for errorHandler with state. (Jared Hanson)

 * Expand test coverage for errorHandler. (Jared Hanson)

 * Add initial test case for errorHandler. (Jared Hanson)

 * Rearrange tests. (Jared Hanson)

 * Export AuthorizationError. (Jared Hanson)

 * Add initial Mocha test suite. (Jared Hanson)

 * Update package.json. (Jared Hanson)

 * Export errorHandler middleware. (Jared Hanson)

 * Update to vows 0.7. (Jared Hanson)

 * Correct spelling in decision middleware. (Jared Hanson)

 * implement immediate callback (Christian Tellnes)

 * Added newline at the end of the file (Frank Hassanabad)

 * Fixed according to the RFC that...The client MUST NOT use the authorization code more than once. (Frank Hassanabad)

 * renamed directory to be all-grants and reverted express2 back to its original state (Frank Hassanabad)

 * Removed the extra extraneous call which doesn't happen due to basic auth giving the error (Frank Hassanabad)

 * Added the implicit grant type to the example (Frank Hassanabad)

 * Exposed and changed the example to work with client credentials grant type (Frank Hassanabad)

 * Fixed typo (Frank Hassanabad)

 * Added password grant to the examples (Frank Hassanabad)

 * allow passing params as third argument to client credentials issued function and state that the refresh token should not be included (Christian Tellnes)

 * Typo fix (cmccall)

 * Update README.md (Enmanuel Toribio)

 * Fix example's basic strategy (Scott Nelson)


2012-07-13, Version 0.1.0
=========================

 * First release!
