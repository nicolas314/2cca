#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import random
import re
from subprocess import Popen, PIPE

DAYS_DEFAULT = 30  # https://man.openbsd.org/openssl.1#days~2
VERSION_PATTERN = re.compile(r'^((?:Open|Libre)SSL) +([\d\.\w]+)')

defaults = {
    'root': {
        'days': 3650,
        'extensions': {
            'basicConstraints': 'critical,CA:true,pathlen:1',
            'keyUsage': 'critical,keyCertSign,cRLSign'
        }
    },
    'sub': {
        'days': 3649,
        'extensions': {
            'basicConstraints': 'critical,CA:true,pathlen:1',
            'keyUsage': 'critical,keyCertSign,cRLSign'
        }
    },
    'server': {
        'days': 3648,
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'critical,digitalSignature,keyEncipherment',
            'extendedKeyUsage': 'serverAuth'
        }
    },
    'client': {
        'days': 730,
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'critical,digitalSignature',
            'extendedKeyUsage': 'clientAuth'
        }
    },
    'www': {
        'days': 730,
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'critical,digitalSignature,keyEncipherment',
            'extendedKeyUsage': 'serverAuth,clientAuth'
        }
    },
    'signcsr': {
        'days': 730,
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'critical,digitalSignature,keyEncipherment',
            'extendedKeyUsage': 'serverAuth,clientAuth'
        }
    }
}


def cert_name(cn):
    return "%s.crt.pem" % cn


def key_name(cn):
    return "%s.key" % cn


def csr_name(cn, cfg = None):
    if cfg and "csr" in cfg:
        return cfg["csr"]
    return "%s.csr" % cn


def config_name(cn):
    return "%s.cnf" % cn


def run(cmd):
    print(cmd)
    os.system(cmd)


def ssl_version():
    ver = ""
    with Popen("openssl version", stdout=PIPE, shell=True) as proc:
        ver = (proc.stdout.read()).decode()

    m = VERSION_PATTERN.match(ver)
    if not m:
        raise RuntimeError(
            "Unknown OpenSSL version: LibreSSL & OpenSSL supported")
    return (m[1], m[2])


def openssl_ecc_supported():
    supp = []
    p = os.popen('openssl ecparam -list_curves', 'r')
    for line in p.readlines():
        fields = line.split(':')
        if len(fields) == 2:
            supp.append(fields[0].strip())
    p.close()
    return supp


def get_config(args):
    ec_supported = None
    cmd = args[0]
    cfg = {'command': cmd}
    for arg in args[1:]:
        fields = arg.split('=')
        if len(fields) == 1:
            cfg[arg] = True
            continue
        if len(fields) != 2:
            continue
        if fields[0] == 'alt':
            if cfg.get('alt') is None:
                cfg['alt'] = list()
            cfg['alt'].append(fields[1])
        elif fields[0] == 'ecc':
            if not ec_supported:
                ec_supported = openssl_ecc_supported()
            if not fields[1] in ec_supported:
                print('unsupported curve:', fields[1])
                print('supported curves:')
                print(ec_supported)
                raise SystemExit
            cfg['ecc'] = fields[1]
        else:
            cfg[fields[0].lower()] = fields[1]
    # Consistency checks
    if cmd in list(defaults.keys()):
        if cfg.get('cn') is None:
            print('Specify a common name with cn=NAME')
            raise SystemExit
        if cfg.get('days') is None:
            cfg['days'] = defaults[cmd]['days']
    if cmd in ['sub', 'server', 'client', 'www', 'crl', 'revoke']:
        if cfg.get('ca') is None:
            print('Specify a CA to use for this operation with ca=NAME')
            raise SystemExit
    cfg['ext'] = '''
        [req]
        distinguished_name=subject
        x509_extensions=v3
        prompt=no
        [subject]
        CN=%(cn)s
''' % cfg
    for elem in ['c', 'o', 'ou', 'st', 'l']:
        if cfg.get(elem):
            cfg['ext'] += elem.upper() + '=' + cfg[elem] + '\n'

    cfg['ext'] += '''
        [v3]
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid,issuer
'''
    # Set extensions according to cert type
    if cfg['command'] in ['root', 'sub', 'server', 'client', 'www']:
        extensions = defaults[cfg['command']]['extensions']
        for ext in list(extensions.keys()):
            cfg['ext'] += '%s=%s\n' % (ext, extensions[ext])

    # Factorize alt into SAN, enforce  SAN for WWW as CN
    if cfg.get('alt') or cfg['command'] == 'www':
        cfg['ext'] += '''
subjectAltName=@alt_names
[alt_names]
'''
        altNames = cfg.get('alt', [])[:]
        if cfg['command'] == 'www':
            altNames.insert(0, cfg['cn'])

        for i, altName in enumerate(altNames):
            cfg['ext'] += 'DNS.%d = %s\n' % (i + 1, altName)

    f = open(cfg['cn'] + '.cnf', 'w')
    for line in (cfg['ext']).split('\n'):
        f.write(line.strip() + '\n')
    f.close()
    return cfg


def generate_serial():
    return hex(random.randint(0x1000000000, 0xFFFFFFFFFF))


def genkey(cfg):
    # Generate key pair
    keycmd = ''
    if cfg.get('ecc'):
        keycmd = 'openssl ecparam -genkey -name %(ecc)s -out "%(cn)s.key"' % cfg
    elif cfg.get('rsa'):
        keycmd = 'openssl genrsa -out "%(cn)s.key" %(rsa)s' % cfg
    else:
        keycmd = 'openssl genrsa -out "%(cn)s.key" 2048' % cfg
    run(keycmd)


def gencsr(cfg):
    cn = cfg['cn']
    cmd = 'openssl req -new -sha256 -key "%(key)s" -out "%(out)s" -config "%(config)s" -extensions v3'
    run(cmd % {
        'key': key_name(cn),
        'out': csr_name(cn),
        'config': config_name(cn)
    })


def gencrt(cfg):
    cn, ca = (cfg['cn'], cfg['ca'])
    cmd = ('openssl x509 -req -sha256 -CA "%(ca_cert)s" -CAkey "%(ca_key)s" '
           '-in "%(in)s" -out "%(out)s" -set_serial %(serial)s -days %(days)s '
           '-extfile "%(config)s" -extensions v3')
    run(
        cmd % {
            'ca_cert': cert_name(ca),
            'ca_key': key_name(ca),
            'in': csr_name(cn, cfg),
            'out': cert_name(cn),
            'serial': generate_serial(),
            'config': config_name(cn),
            'days': cfg.get('days', DAYS_DEFAULT)
        })


def generate_root(cfg):
    # Generate key pair
    genkey(cfg)
    # Generate self-signed certificate
    cn, days = (cfg['cn'], cfg.get('days', DAYS_DEFAULT))
    cmd = (
        'openssl req -new -x509 -key "%(key)s" -extensions v3 -sha256 '
        '-config "%(config)s" -out "%(cert)s" -set_serial %(serial)s -days %(days)s'
    )
    run(
        cmd % {
            'key': key_name(cn),
            'config': config_name(cn),
            'cert': cert_name(cn),
            'days': days,
            'serial': generate_serial()
        })
    os.remove('%(cn)s.cnf' % cfg)


def generate_identity(cfg):
    cn = cfg['cn']
    # Generate key pair
    genkey(cfg)
    # Generate CSR
    gencsr(cfg)
    # Sign CSR with CA
    gencrt(cfg)
    # Delete temporary files
    os.remove(config_name(cn))
    os.remove(csr_name(cn))

def sign_csr(cfg):
    cn = cfg['cn']
    # Sign CSR with CA
    gencrt(cfg)
    # Delete temporary files
    os.remove(config_name(cn))
    #os.remove(csr_name(cn))

def crl_show(cfg):
    print(cfg)


def revoke(cfg):
    print(cfg)


def p12(cfg):
    password = os.environ.get('CA_P12_PASSWORD', None)
    if password is None:
        raise KeyError(
            "Password need to be provided as env var CA_P12_PASSWORD")
    cn, name = (cfg['cn'], cfg.get('name', None))

    # ensure certificate hashes are up to date
    run("openssl certhash ." if libre_ssl else "c_rehash .")

    # generate p12
    cmd = ('openssl pkcs12 -export'
           ' -in %(cert)s'
           ' -inkey %(key)s'
           ' -out %(cn)s.p12'
           ' -chain -CApath .'
           ' -password pass:"%(password)s"')

    if name:
        cmd += ' -name "%(name)s"'

    run(
        cmd % {
            'cert': cert_name(cn),
            'key': key_name(cn),
            'cn': cn,
            'password': password.replace('"', '\\"'),
            'name': name
        })


if __name__ == "__main__":
    global libre_ssl

    if len(sys.argv) == 1:
        print('''
    Available commands:

    2cca root       generate root identity
    2cca sub        generate sub-CA identity
    2cca server     generate openvpn server identity
    2cca client     generate openvpn client identity
    2cca www        generate web server identity

    with params:
        CN=name     mandatory
         O=name     mandatory for root, else inherited from CA
        OU=name     optional
         C=country  optional
         L=locality optional
        ST=state    optional
     email=address  optional
       alt=name1 alt=name2 ...  optional alt names for www
      days=value    optional
       ecc=curve    curve name for ECC
       rsa=size     key size for RSA keys

    2cca crl        show crl
    2cca revoke

    2cca p12        export p12

    with params:
        CN=name     mandatory
        name=name   optional "friendly name" of the key in the generated file

    with environment variable:
        CA_P12_PASSWORD - that contains the password for the new P12 file
''')
        raise SystemExit

    random.seed()
    libre_ssl = ssl_version()[0] == 'LibreSSL'

    {
        'root': generate_root,
        'sub': generate_identity,
        'server': generate_identity,
        'client': generate_identity,
        'www': generate_identity,
        'crl': crl_show,
        'revoke': revoke,
        'p12': p12,
        'signcsr': sign_csr,
    }[sys.argv[1]](get_config(sys.argv[1:]))
