# -*- coding: utf-8 -*-
import os
import sys

defaults={
    'root': {
        'days':3650,
        'ou':'RootCA',
        'extensions': {
            'basicConstraints': 'critical,CA:true,pathlen:1',
            'keyUsage': 'critical,keyCertSign,cRLSign'
        }
    },
    'sub':  {
        'days':3649,
        'ou':'CA',
        'extensions': {
            'basicConstraints': 'critical,CA:true,pathlen:1',
            'keyUsage': 'critical,keyCertSign,cRLSign'
        }
    },
    'server': {
        'days': 3648,
        'ou':'server',
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'digitalSignature, keyEncipherment',
            'extendedKeyUsage':'serverAuth'
        }
    },
    'client': {
        'days': 730,
        'ou': 'client',
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'digitalSignature',
            'extendedKeyUsage':'clientAuth'
        }
    },
    'www': {
        'days': 730,
        'ou': 'server',
        'extensions': {
            'basicConstraints': 'critical,CA:false',
            'keyUsage': 'digitalSignature, keyEncipherment',
            'extendedKeyUsage': 'serverAuth, clientAuth'
        }
    }
}

def run(cmd):
    print cmd
    os.system(cmd)

def get_config(args):
    cmd=args[0]
    cfg = {'command': cmd}
    for arg in args[1:]:
        fields = arg.split('=')
        if len(fields)==1:
            cfg[arg]=True
            continue
        if len(fields)!=2:
            continue
        if fields[0]=='alt':
            if cfg.get('alt')==None:
                cfg['alt']=list()
            cfg['alt'].append(fields[1])
        else:
            cfg[fields[0].lower()]=fields[1]
    # Consistency checks
    if cmd in defaults.keys():
        if cfg.get('cn')==None:
            print 'Specify a common name with cn=NAME'
            raise SystemExit
        cfg['days']=defaults[cmd]['days']
        cfg['ou']=defaults[cmd]['ou']
    if cmd in ['sub', 'server', 'client', 'www', 'crl', 'revoke']:
        if cfg.get('ca')==None:
            print 'Specify a CA to use for this operation with ca=NAME'
            raise SystemExit
    cfg['ext']='''
        [req]
        distinguished_name=subject
        x509_extensions=v3
        prompt=no
        [subject]
        CN=%(cn)s
''' % cfg
    for elem in ['c', 'o', 'ou', 'st', 'l']:
        if cfg.get(elem):
            cfg['ext']+=elem.upper()+'='+cfg[elem]+'\n'

    cfg['ext']+='''
        [v3]
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid,issuer
'''
    # Set extensions according to cert type
    if cfg['command'] in ['root', 'sub', 'server', 'client', 'www']:
        extensions = defaults[cfg['command']]['extensions']
        for ext in extensions.keys():
            cfg['ext']+='%s=%s\n' % (ext, extensions[ext])

    # Factorize alt into SAN
    if cfg.get('alt'):
        cfg['ext']+='''
subjectAltName=@alt_names
[alt_names]
'''
        for i in range(len(cfg['alt'])):
            cfg['ext']+='DNS.%d = %s\n' % (i+1, cfg['alt'][i])

    f=open(cfg['cn']+'.cnf', 'w')
    f.write(cfg['ext'])
    f.close()
    return cfg

def generate_serial():
    f=open('/dev/urandom', 'rb')
    data=f.read(14)
    f.close()
    num='0x2cca'
    for r in data:
        num+='%02x' % ord(r)
    return num

def genkey(cfg):
    # Generate key pair
    keycmd=''
    if cfg.get('ecc'):
        keycmd='openssl ecparam -genkey -name %(ecc)s -out "%(cn)s.key"' % cfg
    elif cfg.get('rsa'):
        keycmd='openssl genrsa -out "%(cn)s.key" %(rsa)s' % cfg
    else:
        keycmd='openssl genrsa -out "%(cn)s.key" 2048' % cfg
    run(keycmd)

def gencsr(cfg):
    cmd='openssl req -new -sha256 -key "%(cn)s.key" -out "%(cn)s.csr"' % cfg
    cmd+=' -config "%(cn)s.cnf"' % cfg
    cmd+=' -extensions v3'
    run(cmd)

def gencrt(cfg):
    cmd='openssl x509 -req -sha256'
    cmd+=' -CA "%(ca)s.crt" -CAkey "%(ca)s.key"' % cfg
    cmd+=' -in "%(cn)s.csr" -out "%(cn)s.crt"' % cfg
    cmd+=' -set_serial %s' % generate_serial()
    if cfg.get('days'):
        cmd+=' -days %(days)s' % cfg
    cmd+=' -extfile "%(cn)s.cnf"' % cfg
    cmd+=' -extensions v3'
    run(cmd)

def generate_root(cfg):
    # Generate key pair
    genkey(cfg)
    # Generate self-signed certificate
    cmd='openssl req -new -x509 -key "%(cn)s.key"' % cfg
    cmd+=' -extensions v3'
    cmd+=' -config "%(cn)s.cnf"' % cfg
    cmd+=' -sha256'
    cmd+=' -out "%(cn)s.crt"' % cfg
    cmd+=' -set_serial %s' % generate_serial()
    run(cmd)
    #os.remove('%(cn)s.cnf' % cfg)

def generate_identity(cfg):
    # Generate key pair
    genkey(cfg)
    # Generate CSR
    gencsr(cfg)
    # Sign CSR with CA
    gencrt(cfg)
    # Delete temporary files
    os.remove('%(cn)s.cnf' % cfg)
    os.remove('%(cn)s.csr' % cfg)

def crl_show(cfg):
    print cfg

def revoke(cfg):
    print cfg

if __name__=="__main__":
    if len(sys.argv)==1:
        print '''
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
'''
        raise SystemExit

    {'root':    generate_root,
     'sub':     generate_identity,
     'server':  generate_identity,
     'client':  generate_identity,
     'www':     generate_identity,
     'crl':     crl_show,
     'revoke':  revoke}[sys.argv[1]](get_config(sys.argv[1:]))

