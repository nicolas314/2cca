# 2cca
2-cent Certification Authority

This program is meant to replace the easy-rsa scripts found in default
installations for OpenVPN.

Two independent versions are provided here:
- Python version (2cca.py) based on pyopenssl
- A C version (in src/) based on OpenSSL

The Python version is placed in the Public Domain. It was used as a
proof-of-concept to demonstrate everything could be done directly with
OpenSSL without involving the command-line tools. It is completely usable
to generate root, server, and client certificates.

The C version is MIT-licensed.

Usage:

- Create Root CA
- Create Server certificate + key and sign it with root
- Create Client certificate + key and sign it with root
- View/update Certificate Revocation List (CRL)

Certificate fields can be specified on the command line, knowing that:
O  will always be included and defaults to "Home"
C  will always be included and defaults to "ZZ", an invalid 2-letter
country identifier
CN will always be included and defaults to "root", "server", or "client"
L, ST, and email are all optional
a single OU will be added as "Root", "Server", or "Client"

You need to create a root first, which will be saved in the current
directory as ca.crt and ca.key. Do not lose the CA key!

You can then create server and client identities as you need.
Identities are saved according to the name you provided, as:
- name.crt
- name.key
- name.p12 for clients. This is useful for some Android OpenVPN clients.

A CRL can be interactively generated or updated if it already exists.

Examples
--------

Create a root:
    2cca root O=ACME C=UK L=Cambridge CN=RootCA email=root@acme

Create a server:
    2cca server C=FR L=Paris CN=openvpn-server email=root@acme-paris

Create a client:
    2cca client C=IT L=Milano CN=openvpn-client

-- nicolas314 - 2015-December

