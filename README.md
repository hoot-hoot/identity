# Identity Service [![Build Status](https://travis-ci.org/truesparrow/identity.svg?branch=master)](https://travis-ci.org/truesparrow/identity) [![Coverage](https://codecov.io/gh/truesparrow/identity/branch/master/graph/badge.svg)](https://codecov.io/gh/truesparrow/identity)

The identity service. This takes care of the main session, identity and auth operations. The actual management of identities is left to Google and GitHub, and we interact with that through [Auth0](https://auth0.com). This service ties all that together in the flow of the application, as well as dealing with application specific things such as sessions, roles etc.