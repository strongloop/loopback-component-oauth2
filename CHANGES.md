2015-01-30, Version 2.0.0-beta4
===============================

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


2014-01-05, Version 1.0.1
=========================

 * Bump version to 1.0.1. (Jared Hanson)

 * Update chai plugins and test cases. (Jared Hanson)

 * Disable Node 0.6 on Travis CI. (Jared Hanson)

 * added a README (AJ ONeal)

 * Update server.test.js (noamcb)

 * Update server.js (noamcb)


2013-09-24, Version 1.0.0
=========================

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

 * Update support files. (Jared Hanson)

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
