# 2cca
2-cent Certification Authority

This program is meant to replace the easy-rsa scripts found in default
installations for OpenVPN.

Two independent versions are provided here:
- Python version (2cca.py) without other dependency than access to the
  'openssl' command.
- A C version (in src/) based on OpenSSL < 1.1.0


Since OpenSSL decided to wreak havoc by mutating their API starting with
version 1.1, I decided to stop supporting the C version (May 2017) and will
continue supporting the Python version instead.

To avoid any dependency on wrapper libraries, the Python version uses the
openssl command directly, producing temporary configuration files and
showing what commands are being executed.

Both versions are MIT-licensed.

Usage:

```
2cca root 
    Create a root CA
    You need to give it a name with CN=NAME
    You may also want to specify:
    - An organization:  O=Bozzos
    - An organization unit: OU=Clowns
    - Some geographical data:
      Country: C=UK
      Locality: L=Cambridge
      State or Province: ST=Cambridgeshire
    - A duration in days -- start validity date is now.
      days=365
    - A key size for an RSA key:
      rsa=4096
    - The name of an elliptic curve instead of RSA:
      ecc=prime256v1

    Example:
    2cca root CN=RootCA O=Bozzos OU=Clowns C=UK L=Cambridge days=365 rsa=4096

2cca sub
    Create a Subordinate CA (optional)
    Same options as above. In addition, you also need to specify which CA
    will sign this new certificate with CA=NAME, like:

    2cca sub CA=RootCA CN=MySubCA O=Bozzos days=364 rsa=4096

2cca server
    Create a server certificate, useful for an OpenVPN server.
    Same options as above. Do not forget to specify the signing CA.

2cca client
    Create a client certificate, useful for an OpenVPN client.
    Same options as above. Do not forget to specify the signing CA.

2cca web
    Create a web server certificate. For this kind of certificate you also
    want to provide Subject Alternative Names using alt=NAME, possibly
    multiple times, like:

    2cca www CA=RootCA CN=www.example.com alt=www.example.com alt=example.com

```

2cca generates one identity per request. An identity is made of:
- A certificate (.crt)
- A private key (.key)
The file names are whatever you used for CN (Common Name). In the above
example you will obtain Root.crt and Root.key in the current directory.

NB: All options names are case-insensitive, i.e. CA=RootCA is the same as
ca=RootCA


Examples
--------

Create a root named RootCA, organisation is ACME, located in Cambridge UK,
use a 2048-bit RSA key (default):

```
    2cca root O=ACME C=UK L=Cambridge CN=RootCA
    -> Generates RootCA.crt and RootCA.key in the current dir
```

Create a server located in Paris FR, use a 2048-bit RSA key, sign it with
the root CA you just created:

```
    2cca server ca=RootCA C=FR L=Paris CN=openvpn-server
    -> Generates openvpn-server.crt and openvpn-server.key
```

Create a client named Marco located in Torino IT:
```
    2cca client ca=RootCA C=IT L=Torino CN=Marco
    -> Generates Marco.crt and Marco.key
```

Security (and lack thereof)
---------------------------

This is not meant to be a PKI, this is meant as a replacement to distribute
keys to clients who want to connect to an OpenVPN server and easily
maintain them. The keys are stored unprotected on the local file system.

For some reason, it was easier for me to write this tool than to try and
understand easy-rsa. Shortest path wins.


TODO
----

- email is not handled yet
- Need to add CRL display and revocation
- Need to add production of P12 files
- Need to add fancy display of all existing certs and their status

-- nicolas314 - 2017-May

