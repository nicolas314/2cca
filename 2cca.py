# -*- coding: utf-8 -*-
# 2CCA: The two-cent Certification Authority
# This source hereby placed in the public domain (2015 December)
#
# This script provides the same functionality as OpenVPN EasyRSA
# It is meant to be a bit more straightforward to use. There are
# three usable options:
# - Create root (CA)
# - Create server certificate, signed by root
# - Create client certificate, signed by root
# Files are all saved in the current directory.
#
import os
import sys
from OpenSSL import crypto

class config:
    # Algorithms are RSA-2048 and SHA-256. Change below if needed.
    key_size=2048
    hash_algo='sha256'
    serialnum_size=8 # Certificate serial number size in bytes
    # Defaults for some certificate fields
    country='ZZ' # ZZ is no valid country
    organization='Home'
    root_name='Root CA'
    root_ou='Root'
    server_ou='Server'
    client_ou='Client'
    duration=10*365*24*60*60 # in days

def set_country(cert):
    print 'Which country is it located in? (default: %s)' % config.country
    print 'Provide a 2-letter country code like US, FR, UK'
    val = raw_input('Country: ')
    if len(val)<1:
        val = config.country
    cert.get_subject().C  = val

def set_city(cert):
    print 'Which city is it located in? (optional)'
    val = raw_input('City: ')
    if len(val)>0:
        cert.get_subject().L  = val

def set_org(cert):
    print 'What organization is it part of? (default: %s)' % config.organization
    val = raw_input('Organization: ')
    if len(val)<1:
        val = config.organization
    cert.get_subject().O  = val

def set_duration(cert):
    print 'Specify a certificate duration in days (default: %d)' % config.duration
    val = raw_input('Duration: ')
    if len(val)<1:
        duration=config.duration
    else:
        duration=int(val)*24*60*60
    cert.gmtime_adj_notAfter(duration)


def build_root():
    # Create certificate template and fill it up
    cert = crypto.X509()

    print 'Give a name to your new root (default: [%s])' % config.root_name
    val = raw_input('Name: ')
    if len(val)<1:
        val = config.root_name
    cert.get_subject().CN = val

    set_country(cert)
    set_city(cert)
    set_org(cert)

    cert.get_subject().OU = config.root_ou

    # Generate key pair
    print '--- generating key pair (%d bits)' % config.key_size
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, config.key_size)

    # Generate random serial
    serial = int(''.join(['%02x' % ord(x) for x in os.urandom(config.serialnum_size)]), 16)
    cert.set_serial_number(serial)

    # Set certificate validity dates
    cert.gmtime_adj_notBefore(0)
    set_duration(cert)

    # Issuer is self
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    # CA extensions
    cert.set_version(2)
    ext = [
    crypto.X509Extension('basicConstraints', True, 'CA:TRUE'),
    crypto.X509Extension('keyUsage', True, 'keyCertSign, cRLSign'),
    crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert)
    ]
    cert.add_extensions(ext)
    # Add key identifier in a second pass otherwise openssl barfs
    ext = [
    crypto.X509Extension('authorityKeyIdentifier', False, 'keyid:always', issuer=cert)
    ]
    cert.add_extensions(ext)

    # Sign certificate
    print '--- self-signing certificate'
    cert.sign(k, config.hash_algo)

    # Save results to root.crt/root.key
    print '--- saving results to root.crt and root.key'
    open('root.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open('root.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print 'done'

def load_root():
    # Read back root certificate and key from root.crt/root.key
    try:
        pem = open('root.crt', 'rt').read()
        root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
        pem = open('root.key', 'rt').read()
        root_key  = crypto.load_privatekey(crypto.FILETYPE_PEM, pem)
    except IOError:
        print 'cannot find root key or certificate'
        print 'generate a root first'
        raise SystemExit

    return root_cert, root_key

def build_server():
    # Load root key and cert
    print '--- loading root certificate and key'
    root_cert, root_key = load_root()

    # Create certificate template for server and fill it up
    cert = crypto.X509()

    print 'Give a name to your new server (default: openvpn-server)'
    server_name = raw_input('Name: ')
    if len(server_name)<1:
        server_name = 'openvpn-server'
    cert.get_subject().CN = server_name

    set_country(cert)
    set_city(cert)

    cert.get_subject().O  = root_cert.get_subject().O
    cert.get_subject().OU = config.server_ou

    # Generate new key pair
    print '--- generating key pair (%d bits)' % config.key_size
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, config.key_size)

    # Generate random serial
    serial = int(''.join(['%02x' % ord(x) for x in os.urandom(config.serialnum_size)]), 16)
    cert.set_serial_number(serial)

    # Set certificate validity dates
    cert.gmtime_adj_notBefore(0)
    set_duration(cert)

    # Set issuer to root
    cert.set_issuer(root_cert.get_subject())
    cert.set_pubkey(k)

    # Set server extensions
    cert.set_version(2)
    ext = [
    crypto.X509Extension('basicConstraints', False, 'CA:FALSE'),
    crypto.X509Extension('nsCertType', False, 'server'),
    crypto.X509Extension('nsComment', False, 'Generated by 2CCA'),
    crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert),
    crypto.X509Extension('authorityKeyIdentifier', False, 'keyid:always,issuer:always', issuer=root_cert),
    crypto.X509Extension('extendedKeyUsage', False, 'serverAuth'),
    crypto.X509Extension('keyUsage', False, 'digitalSignature, keyEncipherment')
    ]
    cert.add_extensions(ext)

    # Sign with root key
    print '--- signing certificate with root'
    cert.sign(root_key, config.hash_algo)

    # Dump results to file
    print '--- saving results to %s.crt and %s.key' % (server_name, server_name)
    open(server_name+'.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(server_name+'.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

def build_client():
    # Load root key and cert
    print '--- loading root certificate and key'
    root_cert, root_key = load_root()

    # Create certificate template for client and fill it up
    cert = crypto.X509()

    print 'Give a name to your new client (default: openvpn-client)'
    client_name = raw_input('Name: ')
    if len(client_name)<1:
        client_name = 'openvpn-client'
    cert.get_subject().CN = client_name

    set_country(cert)
    set_city(cert)
    cert.get_subject().O  = root_cert.get_subject().O
    cert.get_subject().OU = config.client_ou

    # Generate new key pair
    print '--- generating key pair (%d bits)' % config.key_size
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, config.key_size)

    # Generate random serial
    serial = int(''.join(['%02x' % ord(x) for x in os.urandom(config.serialnum_size)]), 16)
    cert.set_serial_number(serial)

    # Set certificate validity dates
    cert.gmtime_adj_notBefore(0)
    set_duration(cert)

    # Set issuer to root
    cert.set_issuer(root_cert.get_subject())
    cert.set_pubkey(k)

    # Set client extensions
    cert.set_version(2)
    ext = [
    crypto.X509Extension('basicConstraints', False, 'CA:FALSE'),
    crypto.X509Extension('nsComment', False, 'Generated by 2CCA'),
    crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert),
    crypto.X509Extension('authorityKeyIdentifier', False, 'keyid:always,issuer:always', issuer=root_cert),
    crypto.X509Extension('extendedKeyUsage', False, 'clientAuth'),
    crypto.X509Extension('keyUsage', False, 'digitalSignature')
    ]
    cert.add_extensions(ext)

    # Sign with root key
    print '--- signing certificate with root'
    cert.sign(root_key, config.hash_algo)

    # Dump results to file
    print '--- saving results to %s.crt and %s.key' % (client_name, client_name)
    open(client_name+'.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(client_name+'.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


if __name__=="__main__":
     
    if len(sys.argv)<2:
        print '''
    Use:

    2cca root               # Create a new Root CA
    2cca server             # Create a server identity
    2cca client             # Create a client identity

'''
        raise SystemExit

    if sys.argv[1]=='root':
        build_root()
    elif sys.argv[1].endswith('server'):
        build_server()
    elif sys.argv[1].endswith('client'):
        build_client()

