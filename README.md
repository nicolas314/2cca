# 2cca
2-cent Certification Authority

This script is meant to replace the easy-rsa scripts found in default
installations for OpenVPN. It is a lot more straightforward to use.
Usage:

- Create Root
- Create Server certificate + key and sign it with root
- Create Client certificate + key and sign it with root

You need to create a root first, which will be saved in the current
directory as root.crt and root.key.

You can then create as many server and client identities as you need.
Answer the questions when you get them. Identities are saved according to
the name you provided, as .crt and .key.

This source is hereby placed in the public domain.

-- nicolas314 - 2015-December

