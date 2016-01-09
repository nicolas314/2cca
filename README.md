# 2cca
2-cent Certification Authority

This program is meant to replace the easy-rsa scripts found in default
installations for OpenVPN.

Two independent versions are provided here:
- Python version (2cca.py) based on pyopenssl
- A single-file C version based on OpenSSL

The Python version is placed in the Public Domain. It was used as a
proof-of-concept to demonstrate everything could be done directly with
OpenSSL without involving the command-line tools. It is completely usable
to generate root, server, and client certificates.

The C version is MIT-licensed. See LICENSE.

Compilation:
Type 'make'. You can also compile it with:

    cc -o 2cca 2cca.c -lcrypto

Tested on:
- ArchLinux on Raspberry Pi -- openssl 1.0.2.e-1
- Debian on x64 -- openssl 1.0.2.e-1

On OSX you cannot use the system openssl libraries but you can substitue
them by libressl, available from brew. I got it to compile with:

    cc -I/usr/local/opt/libressl/include -o 2cca 2cca.c -L/usr/local/opt/libressl/lib -lcrypto

Brew says I am using version 2.3.1 of libressl.

Usage:

- Create Root CA
- Create Sub CA (optional)
- Create Server certificate + key and sign it with a CA
- Create Client certificate + key and sign it with a CA
- View/update Certificate Revocation List (CRL)

Certificate fields can be specified on the command line, knowing that:
- O  will always be included and defaults to "Home"
- C  will always be included and defaults to "ZZ", an invalid 2-letter
country identifier that does not invalidate the certificate.
- CN will always be included and defaults to "root", "sub", "server", or "client".
  For a VPN server you might want to provide something like
  CN=vpn.example.com
- L, ST, and email are all optional. email can only be specified for client
  or server certificates and will be added as a SubjectAltName.
- a single OU will be added as "Root", "Server", or "Client"

Create a root first, saved in the current directory as crt/key files.
Do not lose the CA key!

Optionally, create subordinate CAs. Use '2cca sub' to do so, and indicate
who is the signing CA by name using ca=NAME.

Create server and client identities.
Identities are saved according to the name you provided, as:
- name.crt
- name.key
- name.p12 for clients. This is useful for some Android OpenVPN clients.

The default signing CA is 'root'. If you change the root name or want to
use another CA for signature, use ca=NAME, where NAME is the CN for the CA
you want to use. Example:

    2cca sub ca=root CN=ClientCA    # Generate a subCA for clients
    2cca client ca=ClientCA         # Generate a client with this subCA

Generated keys can be either RSA or elliptic curves.
Without any indication, 2cca will generate 2048-bit RSA keys. This size can
be changed with rsa=xx. If you want ECC keys, use ec=CURVE where CURVE is
supported by your local version of OpenSSL. This can be obtained by
running:

    openssl ecparam -list_curves

Examples:

    # Generate a 1024-bit RSA key for root
    2cca root rsa=1024

    # Generate an ECC key with curve prime256v1
    2cca root ec=prime256v1

Primitive CRL management is also offered. 'crl' displays the contents of
'ca.crl' in the current directory, and 'revoke NAME' allows revocation of a
single certificate by name.

You can also generate Diffie-Hellmann parameters. This is useful for
OpenVPN setups.


Examples
--------

Create a root called RootCA and a subordinate signed by RootCA:

    2cca root O=ACME C=UK L=Cambridge CN=RootCA
    2cca sub C=UK CN=SubCA ca=RootCA

Create a server identity and sign it with SubCA::

    2cca server C=FR L=Paris CN=vpn.example.com email=root@acme-paris ca=SubCA

Create a client identity and sign it with SubCA::

    2cca client C=IT L=Milano CN=openvpn-client ca=SubCA

Display revoked certificates present in the RootCA CRL:

    2cca crl ca=RootCA

Revoke certificate named 'myclient' with myclient.crt in directory. Also
requires the CA private key to sign the CRL.

    2cca revoke myclient ca=SubCA


There is no database of issued certificates to maintain because they use 64
or 128-bit serial numbers, thus are already unique without having to
remember an increasing index.

There is absolutely no key protection whatsoever. You are in charge of
protecting the .key files as you need. For personal VPNs this is not really
an issue, but for something in need of security you probably want to import
keys into smart cards. This is meant to replace easy-rsa, not a
full-fledged PKI.

-- nicolas314 - 2016-January

