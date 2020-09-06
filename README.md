# 2cca
2-cent Certification Authority

This Python script is meant to replace the easy-rsa scripts found in
default installations for OpenVPN. For some reason, it was easier for me to
write this tool than to try and understand easy-rsa. Shortest path wins.

Since OpenSSL decided to wreak havoc by mutating their API starting with
version 1.1, I decided to stop supporting the C version (May 2017) and will
continue supporting the Python version instead.

To avoid any dependency on wrapper libraries, this script uses the openssl
command directly, producing temporary configuration files and showing what
commands are being executed.

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

If you want to have spaces inside values, use double quotes around options:
    2cca root "CN=My Root CA" "O=Bozzos Inc."

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

Create a PKCS#12 (PFX) file:
```
    $ read -s CA_P12_PASSWORD  # 1
    $ export CA_P12_PASSWORD  # 2
    $ 2cca p12 cn=example.org
```

Line 1, 2 above is optional, just make sure that the `CA_P12_PASSWORD`
environment variable has a password set before invoking 2cca.

Security (and lack thereof)
---------------------------

This is not meant to be a PKI, this is meant as a replacement to distribute
keys to clients who want to connect to an OpenVPN server and easily
maintain them. The keys are stored unprotected on the local file system.

openssl commands are executed using 'system' so don't use any untrusted
user inputs when calling this script. This is meant to be executed by a
single person on a preferrably air-gapped machine when generating keys for
groups of people who need VPN access.


TODO
----

- email is not handled yet
- Need to add CRL display and revocation
- Need to add fancy display of all existing certs and their status

-- nicolas314 - 2017-May

