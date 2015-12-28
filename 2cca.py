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
import glob
import time
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
    duration=10*365 # in days
    # Default base file name for root files
    root='ca'

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
        duration=config.duration*24*60*60
    else:
        duration=int(val)*24*60*60
    cert.gmtime_adj_notAfter(duration)


def build_root():
    if os.path.exists(config.root+'.crt') and os.path.exists(config.root+'.key'):
        print 'A root already exists in this directory. Exiting now'
        raise SystemExit

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
    print 'Generating key pair (%d bits)' % config.key_size
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
    cert.sign(k, config.hash_algo)

    # Save root crt and key
    print 'Saving results to %s.crt and %s.key' % (config.root, config.root)
    open(config.root+'.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(config.root+'.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print 'done'

def load_root():
    # Read back root certificate and key
    try:
        pem = open(config.root+'.crt', 'rt').read()
        root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
        pem = open(config.root+'.key', 'rt').read()
        root_key  = crypto.load_privatekey(crypto.FILETYPE_PEM, pem)
    except IOError:
        print 'Cannot find root key or certificate. Generate a root first'
        raise SystemExit

    return root_cert, root_key

def load_crl():
    try:
        pem = open(config.root+'.crl', 'rt').read()
        root_crl = crypto.load_crl(crypto.FILETYPE_PEM, pem)
    except IOError:
        root_crl = None
    return root_crl

def build_server():
    # Load root key and cert
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
    print 'Generating key pair (%d bits)' % config.key_size
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
    cert.sign(root_key, config.hash_algo)

    # Dump results to file
    print 'Saving results to %s.crt and %s.key' % (server_name, server_name)
    open(server_name+'.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(server_name+'.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print 'done'

def build_client():
    # Load root key and cert
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
    print 'Generating key pair (%d bits)' % config.key_size
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
    cert.sign(root_key, config.hash_algo)

    # Dump results to file
    print 'Saving results to: %s.[crt|key|p12]' % (client_name,)
    open(client_name+'.crt', 'w').write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(client_name+'.key', 'w').write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    # Create a password-less p12, useful for some Android clients
    p12 = crypto.PKCS12()
    p12.set_ca_certificates([root_cert])
    p12.set_privatekey(k)
    p12.set_certificate(cert)
    pem=p12.export()
    open(client_name+'.p12', 'w').write(pem)
    print 'done'

def nice_date(d):
    return '%s-%s-%s' % (d[:4], d[4:6], d[6:8])

def now():
    n=time.gmtime()
    return '%4d%02d%02d%02d%02d%02dZ' % (n[0], n[1], n[2], n[3], n[4], n[5])

def update_crl():
    # Load root key and cert
    root_cert, root_key = load_root()

    # Load CRL if one is found in current directory
    root_crl = load_crl()
    if root_crl:
        print 'Found %s.crl' % (config.root,)
        # Identify revoked certs
        print
        print 'Revoked serial numbers:'
        print 'serial'
        for rev in root_crl.get_revoked():
            print rev.get_serial().lower()
    else:
        root_crl=crypto.CRL()

    # List certificates in current directory
    print
    print 'Certificates in current directory:'
    known_certs=glob.glob('*.crt')
    # Remove root cert from list, cannot revoke itself
    known_certs.remove(config.root+'.crt')
    if len(known_certs)<1:
        print 'none found'
        return

    name2serial={}
    print '%-16s %-20s %-15s %-15s' % ('serial', 'name', 'from', 'to')
    for certname in known_certs:
        f=open(certname, 'rt')
        pem=f.read()
        f.close()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
        serial=hex(cert.get_serial_number())[2:-1]
        name2serial[certname[:-4]]=serial
        print '%-16s %-20s %-15s %-15s' % (serial,
                               certname[:-4],
                               nice_date(cert.get_notBefore()),
                               nice_date(cert.get_notAfter()))
    while 1:
        print
        req = raw_input('Certificate to revoke by name (return to exit): ')
        if len(req)<1:
            return
        if not req in name2serial.keys():
            print 'cannot find:', req
        else:
            break
            
    rev = crypto.Revoked()
    rev.set_serial(name2serial[req])
    rev.set_reason('unspecified')
    rev.set_rev_date(now())

    # Update CRL
    root_crl.add_revoked(rev)
    # Sign CRL
    crl_text = root_crl.export(root_cert, root_key, crypto.FILETYPE_PEM, days=365)
    # Publish CRL
    f=open(config.root+'.crl', 'w')
    f.write(crl_text)
    f.close()
    return

if __name__=="__main__":
     
    if len(sys.argv)<2:
        print '''
    Use:

    2cca root               # Create a new Root CA
    2cca server             # Create a server identity
    2cca client             # Create a client identity

    2cca crl                # Revoke certificates

'''
        raise SystemExit

    if sys.argv[1]=='root':
        build_root()
    elif sys.argv[1]=='server':
        build_server()
    elif sys.argv[1]=='client':
        build_client()
    elif sys.argv[1]=='crl':
        update_crl()


