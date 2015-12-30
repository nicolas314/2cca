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

Usage:

- Create Root CA
- Create Server certificate + key and sign it with root
- Create Client certificate + key and sign it with root
- View/update Certificate Revocation List (CRL)

Certificate fields can be specified on the command line, knowing that:
- O  will always be included and defaults to "Home"
- C  will always be included and defaults to "ZZ", an invalid 2-letter
country identifier that does not invalidate the certificate.
- CN will always be included and defaults to "root", "server", or "client".
  For a VPN server you might want to provide something like
  CN=vpn.example.com
- L, ST, and email are all optional
- a single OU will be added as "Root", "Server", or "Client"

You need to create a root first, which will be saved in the current
directory as ca.crt and ca.key. Do not lose the CA key!

You can then create server and client identities as you need.
Identities are saved according to the name you provided, as:
- name.crt
- name.key
- name.p12 for clients. This is useful for some Android OpenVPN clients.

Primitive CRL management is also offered. 'crl' displays the contents of
'ca.crl' in the current directory, and 'revoke NAME' allows revocation of a
single certificate by name.

Examples
--------

Create a root:

    2cca root O=ACME C=UK L=Cambridge CN=RootCA email=root@acme

Create a server:

    2cca server C=FR L=Paris CN=vpn.example.com email=root@acme-paris

Create a client:

    2cca client C=IT L=Milano CN=openvpn-client

Display revoked certificates present in ca.crl:

    2cca crl

Revoke certificate named 'myclient' with myclient.crt in directory. Also
requires the CA private key to sign the CRL.

    2cca revoke myclient


There is no database of issued certificates to maintain because they use 64
or 128-bit serial numbers, thus are already unique without having to
remember an increasing index.

There is absolutely no key protection whatsoever. You are in charge of
protecting the .key files as you need. For personal VPNs this is not really
an issue, but for something in need of security you probably want to import
keys into smart cards. This is meant to replace easy-rsa, not a
full-fledged PKI.

-- nicolas314 - 2015-December

