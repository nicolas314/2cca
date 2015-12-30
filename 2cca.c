/*
 * Two-cent Certification Authority: the C version
 * This utility is meant to replace easy-rsa in openvpn distributions.
 * It makes it easier to generate a root CA, server, or client certs.
 *
 * (c) nicolas314 -- MIT license
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define RSA_KEYSZ   2048
#define FIELD_SZ    128
#define SERIAL_SZ   16  /* in bytes */
#define ROOT_BNAME  "ca"

/* Use to shuffle root key+cert around */
typedef struct _root_ {
    EVP_PKEY * key ;
    X509    * cert ;
} root ;

/* Input value storage */
static struct {
    char o [FIELD_SZ+1];
    char cn[FIELD_SZ+1];
    char c [FIELD_SZ+1];
    int  duration ;
    char l [FIELD_SZ+1];
    char st[FIELD_SZ+1];
    char email[FIELD_SZ+1] ;
} certinfo ;

/*
 * Set one extension in a given certificate
 */
static int set_extension(X509 * issuer, X509 * cert, int nid, char * value)
{
    X509_EXTENSION * ext ;
    X509V3_CTX ctx ;

    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext)
        return -1;

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return 0 ;
}

/*
 * Set serial to a random 128-bit number
 */
static int set_serial128(X509 * cert)
{
    FILE * urandom;
    BIGNUM *        b_serial ;
    unsigned char   c_serial[SERIAL_SZ] ;

    /* Read random bits from /dev/urandom */
    urandom = fopen("/dev/urandom", "rb");
    fread(c_serial, SERIAL_SZ, 1, urandom);
    fclose(urandom);

    b_serial = BN_bin2bn(c_serial, SERIAL_SZ, NULL);
    BN_to_ASN1_INTEGER(b_serial, X509_get_serialNumber(cert));
    BN_free(b_serial);
    return 0 ;
}

/*
 * Useful for showing progress on key generation
 */
static void progress(int p, int n, void *arg)
{
    char c='B';
    switch (p) {
        case 0: c='.'; break;
        case 1: c='+'; break;
        case 2: c='*'; break;
        default: c='\n'; break;
    }
    fputc(c, stderr);
}

/*
 * Load root certificate and private key from current dir
 */
static int load_root(root * ca)
{
    FILE * f ;
    RSA  * rsa ;

    if ((f=fopen(ROOT_BNAME ".crt", "r"))==NULL) {
        return -1 ; 
    }
    ca->cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    if ((f=fopen(ROOT_BNAME ".key", "r"))==NULL) {
        return -1 ; 
    }
    rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    ca->key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(ca->key, rsa);

    if (!X509_check_private_key(ca->cert, ca->key)) {
        fprintf(stderr, "CA certificate and private key do not match\n");
        return -1 ;
    }
    return 0;
}

/*
 * Build a new root CA, i.e. a self-signed certificate
 */
int build_root(void)
{
    EVP_PKEY * pkey ;
    RSA * rsa ;
    X509 * cert ;
    X509_NAME * name ;
    FILE * pem ;

    /* Check before overwriting */
    if ((access(ROOT_BNAME ".crt", F_OK)!=-1) || (access(ROOT_BNAME ".key", F_OK)!=-1)) {
        fprintf(stderr, "A root already exists in this directory. Exiting now\n");
        return -1 ;
    }


    /* Generate key pair */
    printf("Generating RSA-%d key\n", RSA_KEYSZ);
    pkey = EVP_PKEY_new();
    rsa = RSA_generate_key(RSA_KEYSZ, RSA_F4, progress, 0);
    EVP_PKEY_assign_RSA(pkey, rsa);

    /* Assign all certificate fields */
    cert = X509_new();
    X509_set_version(cert, 2);
    set_serial128(cert);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), certinfo.duration * 24*60*60);
    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, certinfo.c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, certinfo.o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, certinfo.cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "Root", -1, -1, 0);
    if (certinfo.l[0]) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, certinfo.l, -1, -1, 0);
    }
    if (certinfo.email[0]) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, certinfo.email, -1, -1, 0);
    }
    if (certinfo.st[0]) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, certinfo.st, -1, -1, 0);
    }

    /* Root can issue certs and sign CRLS */
    set_extension(cert, cert, NID_basic_constraints, "critical,CA:TRUE");
    set_extension(cert, cert, NID_subject_key_identifier, "hash");
    set_extension(cert, cert, NID_authority_key_identifier, "issuer:always,keyid:always");
    set_extension(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");

    X509_set_issuer_name(cert, name);
    X509_sign(cert, pkey, EVP_sha256());

    printf("Saving results to %s.[crt|key]\n", ROOT_BNAME);
    pem = fopen(ROOT_BNAME ".key", "wb");
    PEM_write_PrivateKey(pem, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pem);
    pem = fopen(ROOT_BNAME ".crt", "wb");
    PEM_write_X509(pem, cert);
    fclose(pem);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    printf("done\n");

    return 0;
}

/*
 * Build a new server certificate for OpenVPN
 */
int build_server(void)
{
    EVP_PKEY * pkey ;
    RSA * rsa ;
    X509 * cert ;
    X509_NAME * name ;
    FILE * pem ;
    root ca ;
    char filename[FIELD_SZ+4];

    if (load_root(&ca)!=0) {
        fprintf(stderr, "Cannot find root key or certificate. Generate a root first\n");
        return -1 ;
    }
    /* Organization is the same as root */
    X509_NAME_get_text_by_NID(X509_get_subject_name(ca.cert),
                              NID_organizationName,
                              certinfo.o,
                              FIELD_SZ);

    /* Generate key pair */
    printf("Generating RSA-%d key\n", RSA_KEYSZ);
    pkey = EVP_PKEY_new();
    rsa = RSA_generate_key(RSA_KEYSZ, RSA_F4, progress, 0);
    EVP_PKEY_assign_RSA(pkey, rsa);

    /* Assign all certificate fields */
    cert = X509_new();
    X509_set_version(cert, 2);

    set_serial128(cert);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), certinfo.duration * 24*60*60);
    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, certinfo.c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, certinfo.o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "Server", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, certinfo.cn, -1, -1, 0);
    if (certinfo.l[0]) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, certinfo.l, -1, -1, 0);
    }
    if (certinfo.email[0]) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, certinfo.email, -1, -1, 0);
    }
    if (certinfo.st[0]) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, certinfo.st, -1, -1, 0);
    }

    X509_set_issuer_name(cert, X509_get_subject_name(ca.cert));
    set_extension(ca.cert, cert, NID_basic_constraints, "CA:FALSE");
    set_extension(ca.cert, cert, NID_netscape_cert_type, "server");
    set_extension(ca.cert, cert, NID_netscape_comment, "Generated by 2CCA");
    set_extension(ca.cert, cert, NID_subject_key_identifier, "hash");
    set_extension(ca.cert, cert, NID_authority_key_identifier, "issuer:always,keyid:always");
    set_extension(ca.cert, cert, NID_anyExtendedKeyUsage, "serverAuth");
    set_extension(ca.cert, cert, NID_key_usage, "digitalSignature,keyEncipherment");

    X509_sign(cert, ca.key, EVP_sha256());

    printf("Saving results to %s.[crt|key]\n", certinfo.cn);
    sprintf(filename, "%s.key", certinfo.cn);
    pem = fopen(filename, "wb");
    PEM_write_PrivateKey(pem, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pem);

    sprintf(filename, "%s.crt", certinfo.cn);
    pem = fopen(filename, "wb");
    PEM_write_X509(pem, cert);
    fclose(pem);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    X509_free(ca.cert);
    EVP_PKEY_free(ca.key);

    printf("done\n");

}

/*
 * Build a new client certificate for OpenVPN
 */
int build_client(void)
{
    EVP_PKEY * pkey ;
    RSA * rsa ;
    X509 * cert ;
    X509_NAME * name ;
    FILE * pem ;
    root ca ;
    char filename[FIELD_SZ+4];

    if (load_root(&ca)!=0) {
        fprintf(stderr, "Cannot find root key or certificate. Generate a root first\n");
        return -1 ;
    }
    /*
     * Organization is the same as root
     */
    X509_NAME_get_text_by_NID(X509_get_subject_name(ca.cert),
                              NID_organizationName,
                              certinfo.o,
                              FIELD_SZ);

    /* Generate key pair */
    printf("Generating RSA-%d key\n", RSA_KEYSZ);
    pkey = EVP_PKEY_new();
    rsa = RSA_generate_key(RSA_KEYSZ, RSA_F4, progress, 0);
    EVP_PKEY_assign_RSA(pkey, rsa);

    /* Create certificate bag and fill it up */
    cert = X509_new();
    X509_set_version(cert, 2);

    set_serial128(cert);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), certinfo.duration * 24*60*60);
    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, certinfo.c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, certinfo.o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "Client", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, certinfo.cn, -1, -1, 0);
    if (certinfo.l[0]) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, certinfo.l, -1, -1, 0);
    }
    if (certinfo.email[0]) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, certinfo.email, -1, -1, 0);
    }
    if (certinfo.st[0]) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, certinfo.st, -1, -1, 0);
    }

    X509_set_issuer_name(cert, X509_get_subject_name(ca.cert));
    set_extension(ca.cert, cert, NID_basic_constraints, "CA:FALSE");
    set_extension(ca.cert, cert, NID_netscape_comment, "Generated by 2CCA");
    set_extension(ca.cert, cert, NID_subject_key_identifier, "hash");
    set_extension(ca.cert, cert, NID_authority_key_identifier, "issuer:always,keyid:always");
    set_extension(ca.cert, cert, NID_anyExtendedKeyUsage, "clientAuth");
    set_extension(ca.cert, cert, NID_key_usage, "digitalSignature");

    X509_sign(cert, ca.key, EVP_sha256());

    printf("Saving results to %s.[crt|key]\n", certinfo.cn);
    sprintf(filename, "%s.key", certinfo.cn);
    pem = fopen(filename, "wb");
    PEM_write_PrivateKey(pem, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pem);

    sprintf(filename, "%s.crt", certinfo.cn);
    pem = fopen(filename, "wb");
    PEM_write_X509(pem, cert);
    fclose(pem);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    X509_free(ca.cert);
    EVP_PKEY_free(ca.key);

    printf("done\n");
}


int update_crl(void)
{
    fprintf(stderr, "not implemented yet\n");
    return -1 ;
}


void usage(void)
{
    printf(
        "\n"
        "\tUse:\n"
        "\t2cca root   [DN] [duration=xx] # Create a root\n"
        "\t2cca server [DN] [duration=xx] # Create a server\n"
        "\t2cca client [DN] [duration=xx] # Create a client\n"
        "\n"
        "Where DN is given as key=val pairs. Supported fields:\n"
        "\n"
        "\tO     Organization, only for root (default: Home)\n"
        "\tCN    Common Name (default: root|server|client\n"
        "\tC     2-letter country code like US, FR, UK (default: ZZ)\n"
        "\tST    a state name (optional)\n"
        "\tL     a locality or city name (optional)\n"
        "\temail an email address\n"
        "\n"
        "Certificate duration in days\n"
        "\n"
        "\t2cca crl             # Revoke certificates\n"
        "\n"
    );
}

int parse_cmd_line(int argc, char ** argv)
{
    int i ;
    char key[FIELD_SZ] ;
    char val[FIELD_SZ] ;

    for (i=2 ; i<argc ; i++) { 
        if (sscanf(argv[i], "%[^=]=%s", key, val)==2) {
            if (!strcmp(key, "O")) {
                strcpy(certinfo.o, val);
            } else if (!strcmp(key, "C")) {
                strcpy(certinfo.c, val);
            } else if (!strcmp(key, "ST")) {
                strcpy(certinfo.st, val);
            } else if (!strcmp(key, "CN")) {
                strcpy(certinfo.cn, val);
            } else if (!strcmp(key, "L")) {
                strcpy(certinfo.l, val);
            } else if (!strcmp(key, "email")) {
                strcpy(certinfo.email, val);
            } else if (!strcmp(key, "duration")) {
                certinfo.duration = atoi(val);
            } else {
                fprintf(stderr, "Unsupported field: [%s]\n", key);
                return -1 ;
            }
        }
    }
    return 0 ;
}

int main(int argc, char * argv[])
{
	if (argc<2) {
        usage();
		return 1 ;
	}

    OpenSSL_add_all_algorithms();

    /* Initialize DN fields to default values */
    strcpy(certinfo.o, "Home");
    strcpy(certinfo.c, "ZZ");
    certinfo.duration = 3650 ;
    certinfo.l[0]=0 ;
    certinfo.cn[0]=0 ;
    certinfo.st[0]=0 ;
    certinfo.email[0]=0 ;

    if ((argc>2) && (parse_cmd_line(argc, argv)!=0)) {
        return -1 ;
    }

    if (certinfo.cn[0]==0) {
        strcpy(certinfo.cn, argv[1]);
    }

    if (!strcmp(argv[1], "root")) {
        build_root();
    } else if (!strcmp(argv[1], "server")) {
        build_server() ;
    } else if (!strcmp(argv[1], "client")) {
        build_client() ;
    } else if (!strcmp(argv[1], "crl")) {
        update_crl();
    }
	return 0 ;
}

