Public key management for EdDSA JSON Web Tokens
===============================================

This package provides a full key management solution for EdDSA keys.

It is seperated into 4 components:

1. An implementation of JSON Web keys and sets thereof used by all other components.
2. A server used to store public keys for token validation.
3. A validation component that can be integrated into any application.
4. A generation component that can be integrated into any application.

The implementation of JWKs is intended for internal use but can also be integrated into other applications.
This use-case may not be tested though.

Using the keyserver as part of an already running webserver is currently not supported
and not advisable due to creating additional security risks.

The validation component can be used anywhere a JWT is received and has to be validated.
It does currently only support Ed25519 since there is no stable Ed448 implementation in Go.

Be careful when using the generation component as it stores the private key necessary to generate JWTs.
To ensure the greatest amount of security, it should be run in an isolated environment with appropriate protection.
The private keys are never written to disk but instead stored in RAM while the application is running.
Restarting the application will generate a new key set and submit the public key to the keyserver.