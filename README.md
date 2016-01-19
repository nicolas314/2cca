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

Compilation
-----------

Use 'make'. You can also compile with:

    cc -o 2cca 2cca.c -lcrypto

Tested on:
- ArchLinux on Raspberry Pi -- openssl 1.0.2.e-1
- Debian on x64 -- openssl 1.0.2.e-1

On OSX you cannot use the system openssl libraries but you can substitue
them by libressl, available from brew. I got it to compile with:

    export LIBRE=/usr/local/opt/libressl
    cc -I$(LIBRE)/include -L$(LIBRE)/lib -o 2cca 2cca.c -lcrypto

Brew says I am using version 2.3.1 of libressl.

What it does
------------

2cca can generate certificates and keys for various roles.
Supported roles are:
- Root CA: a self-signed Certification Authority
- Sub CA: a Certification Authority, signed by another CA
- OpenVPN server
- OpenVPN client
- Web server

Specify which kind of certificate you want to create and indicate which
fields and properties are needed. A certificate file and key will be
created in the local directory in PEM format.

Usage
-----

Creating certificates follows the same syntax for all types of
certificates:

    2cca TYPE [properties]

    TYPE        Description
    ----        -----------
    root        Create a (self-signed) root CA certificate
    sub         Create a Subordinate CA certificate
    server      Create an OpenVPN server certificate
    client      Create an OpenVPN client certificate
    www         Create a Web server certificate

Certificate fields and properties are specified on the command line by
specifying a list of key=value blocks. If the value contains blanks,
surround the whole block with double or simple quotes. Supported keys and
their meaning are:

    Key      Meaning                 Example                     Default
    ---      -------                 -------                     -------
    O        Organisation            "O=ACME Inc"                O=Home
    C        Country 2-letter code   C=UK                        C=ZZ
    CN       Common Name             CN=MyServer                 same as TYPE
    L        Locality or City        L=Munich                    none
    ST       State                   ST=Bavaria                  none
    email    Email                   email=root@example.com      none
    ca       Signing CA              ca=Sub                      ca=root
    duration Duration                duration=15                 duration=365
    dns      Host name               dns=www.example.com         none

    The OU field (Organizational Unit) is automatically set by certificate
    type:

    Type    OU
    ----    --
    root    OU=Root
    sub     OU=Sub
    server  OU=Server
    client  OU=Client
    www     OU=Server 


File names
----------

Certificate and key are saved in the current directory as CN.crt and
CN.key, where CN is the requested Common Name. For client identities, a
password-less P12 is also generated.

The default signing CA is named CN=root. If you change the root name
(CN=xx) or want to use a specific CA for signature, use ca=NAME, where NAME
is the CN for the CA you want to use. Example:

    # Generate a root called MyROOT:
    2cca root CN=MyROOT C=UK
    -> Generates MyROOT.crt and MyROOT.key

    # Generate a Sub CA called MySUB and sign it with MyROOT:
    2cca sub ca=MyROOT CN=MySUB C=UK
    -> Generates MySUB.crt and MySUB.key, signed by MyROOT

    # Generate a client certificate for 'joe' and sign it with MySUB:
    2cca client ca=MySUB CN=joe C=UK
    -> Generates joe.crt, joe.key, joe.p12, signed by MySUB

    # If you want to verify the chain with openssl:
    cat MyROOT.crt MySUB.crt > bundle
    openssl verify -CAfile bundle joe.crt
    -> joe.crt: OK

Certificate Duration
--------------------

Change certificate duration using duration=xx where xx is in days from
today. Default certificate duration is 3650 days. Example:

    # Generate a client certificate for 15 days:
    2cca client duration=15 ca=MyROOT

Crypto Parameters
-----------------

You can generate RSA keys by specifying a key size with rsa=xx
Example:

    Generate a root certificate with a 4096 RSA key:
    2cca root rsa=4096

You can also generate elliptic-curve keys for clients and servers. Use
ec=curve, where curve is one of the named curves supported by openssl. You
can get a list of elliptic curves supported on your system by running:

    openssl ecparam -list_curves

Examples:

    # Generate a client cert with an ECC key with curve prime256v1
    2cca client ec=prime256v1

The default hash function is sha256. There is currently no way to change
this from the command-line.


Certificate Revocation Lists
----------------------------

Primitive CRL management is also offered. The two associated commands are:

    2cca revoke NAME ca=xx
    2cca crl ca=xx

You revoke a certificate by name, i.e. by CN, which also happens to be the
base file name. To revoke joe's certificate issued by MySUB:

    # Revoke joe issued by MySUB
    2cca revoke joe ca=MySUB

You can review the CRL for a CA like this:

    # See CRL for ca=MySUB
    2cca crl ca=MySUB
    -- Revoked certificates found in CRL
    serial: 2CCA95D9A9F95BEE6C44564E0A514B45
    date: Jan 19 22:04:51 2016 GMT

    # Display the CRL using openssl
    openssl crl -in MySUB.crl -text


Diffie-Hellmann Parameters
--------------------------

You can also generate Diffie-Hellmann parameters. Useful for OpenVPN
setups.

    # Generate DH-2048 parameters
    2cca dh
    Generating DH parameters (2048 bits) -- this can take long
    done

It takes ages to generate these, and the command does not display any
progress. You probably want to do it with OpenSSL. I just coded it for
convenience when the openssl command is not present.


Complete Example
----------------

Starting from scratch, you want to first create a root (self-signed) CA.
It will be named 'MyRoot', for a duration of 1000 days, have a 1024-bit RSA
key, and be based in the UK.

    2cca root CN=MyRoot duration=1000 rsa=1024 C=UK

Check that you now have MyRoot.crt and MyRoot.key in the current directory.

You want two Sub-CAs then: one to handle OpenVPN servers and clients, and
another one to handle WWW server certificates. Both are children of the
root you just created.

    # Generate the OpenVPN CA named 'VPNCA' for 900 days, 1024-bit RSA:
    2cca sub CN=VPNCA duration=900 rsa=1024 ca=MyRoot C=UK
    # Generate the www server CA named 'WWWCA' for 500 days, 1024-bit RSA:
    2cca sub CN=WWWCA duration=500 rsa=1024 ca=MyRoot C=UK

You now have VPNCA.[crt|key] and WWWCA.[crt|key] in the current directory.

Let us now issue client and server certificates for OpenVPN with the
appropriate CA. We will use 512-bit RSA keys and set a validity period of
one year for the server, and two weeks for the client.

    # Generate a cert for server named 'vpn-server' for 365 days, 512-bit RSA:
    2cca server ca=VPNCA duration=365 CN=vpn-server rsa=512 C=UK
    # Generate a cert for a client named 'joe' for 15 days, 512-bit RSA:
    2cca client ca=VPNCA duration=15 CN=joe rsa=512 C=UK

You can now install vpn-server.[crt|key] in the appropriate places and send
the client credentials to Joe: either send joe.[crt|key] or joe.p12

Let us issue a web server certificate for a server named 'www.example.com'
for a duration of one year, with a 2048-bit RSA key:

    # Generate a web server certificate
    2cca www ca=WWWCA duration=365 rsa=2048 CN=www.example.com dns=www.example.com

Check that you have files called
www.example.com.[crt|key] in the current directory.

You can also issue certificates that arte valid for multiple domains or
joker certificates by issuing several dns= properties on the command-line.
Example:

    # Generate a certificate for *.dom1.abc and *.dom2.abc
    2cca www ca=WWWCA "dns=*.dom1.abc" "dns=*.dom2.abc"

Warnings
--------

There is no database of issued certificates to maintain because they use
128-bit serial numbers, thus are already unique without having to remember
an increasing index.

There is absolutely no key protection whatsoever. You are in charge of
protecting the .key files as you need. For personal VPNs this is not really
an issue, but for something in need of security you probably want to import
keys into smart cards. This is meant to replace easy-rsa, not a
full-fledged PKI.

-- nicolas314 - 2016-January

