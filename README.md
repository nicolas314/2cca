# 2cca
2-cent Certification Authority
This source is hereby placed in the public domain.


This script is meant to replace the easy-rsa scripts found in default
installations for OpenVPN.

Usage:

- Create Root CA
- Create Server certificate + key and sign it with root
- Create Client certificate + key and sign it with root
- View/update Certificate Revocation List (CRL)

You need to create a root first, which will be saved in the current
directory as ca.crt and ca.key. Do not lose the CA key!

You can then create server and client identities as you need.
Identities are saved according to the name you provided, as:
- name.crt
- name.key
- name.p12 for clients. This is useful for some Android OpenVPN clients.

A CRL can be interactively generated or updated if it already exists.

-- nicolas314 - 2015-December

