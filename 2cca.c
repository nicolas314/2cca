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

/* Use to shuffle key+cert around */
typedef struct _identity_ {
    EVP_PKEY * key ;
    X509    * cert ;
} identity ;

/* Input value storage */
typedef struct _certinfo_ {
    char o [FIELD_SZ+1];
    char ou[FIELD_SZ+1];
    char cn[FIELD_SZ+1];
    char c [FIELD_SZ+1];
    int  duration ;
    char l [FIELD_SZ+1];
    char st[FIELD_SZ+1];
    char email[FIELD_SZ+1] ;

    enum {
        PROFILE_UNKNOWN=0,
        PROFILE_ROOT_CA,
        PROFILE_SUB_CA,
        PROFILE_SERVER,
        PROFILE_CLIENT
    } profile ;
    char signing_ca[FIELD_SZ+1];
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
 * Load CA certificate and private key from current dir
 */
static int load_ca(char * ca_name, identity * ca)
{
    FILE * f ;
    RSA  * rsa ;
    char filename[FIELD_SZ+1] ;

    sprintf(filename, "%s.crt", ca_name);
    if ((f=fopen(filename, "r"))==NULL) {
        fprintf(stderr, "Cannot find: %s\n", filename);
        return -1 ; 
    }
    ca->cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    sprintf(filename, "%s.key", ca_name);
    if ((f=fopen(filename, "r"))==NULL) {
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
 * Create identity
 */
int build_identity(certinfo * ci)
{
    EVP_PKEY * pkey ;
    RSA * rsa ;
    X509 * cert ;
    X509_NAME * name ;
    identity ca ;
    char filename[FIELD_SZ+5];
    FILE * pem ;

    /* Check before overwriting */
    sprintf(filename, "%s.crt", ci->cn);
    if (access(filename, F_OK)!=-1) {
        fprintf(stderr, "identity named %s already exists in this directory. Exiting now\n", filename);
        return -1 ;
    }
    sprintf(filename, "%s.key", ci->cn);
    if (access(filename, F_OK)!=-1) {
        fprintf(stderr, "identity named %s already exists in this directory. Exiting now\n", filename);
        return -1 ;
    }

    switch (ci->profile) {
        case PROFILE_ROOT_CA:
        strcpy(ci->ou, "Root");
        break;

        case PROFILE_SUB_CA:
        strcpy(ci->ou, "Sub");
        break;

        case PROFILE_SERVER:
        strcpy(ci->ou, "Server");
        break;
        
        case PROFILE_CLIENT:
        strcpy(ci->ou, "Client");
        break;

        default:
        fprintf(stderr, "Unknown profile: aborting\n");
        return -1 ;
    }

    if (ci->profile != PROFILE_ROOT_CA) {
        /* Need to load signing CA */
        if (load_ca(ci->signing_ca, &ca)!=0) {
            fprintf(stderr, "Cannot find CA key or certificate\n");
            return -1 ;
        }
        /* Organization is the same as root */
        X509_NAME_get_text_by_NID(X509_get_subject_name(ca.cert),
                                  NID_organizationName,
                                  ci->o,
                                  FIELD_SZ);
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
    X509_gmtime_adj(X509_get_notAfter(cert), ci->duration * 24*60*60);
    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)ci->c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)ci->o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)ci->cn, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)ci->ou, -1, -1, 0);
    if (ci->l[0]) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *)ci->l, -1, -1, 0);
    }
    if (ci->st[0]) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)ci->st, -1, -1, 0);
    }

    /* Set extensions according to profile */
    switch (ci->profile) {
        case PROFILE_ROOT_CA:
        /* CA profiles can issue certs and sign CRLS */
        set_extension(cert, cert, NID_basic_constraints, "critical,CA:TRUE");
        set_extension(cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
        set_extension(cert, cert, NID_subject_key_identifier, "hash");
        set_extension(cert, cert, NID_authority_key_identifier, "keyid:always");
        break ;

        case PROFILE_SUB_CA:
        /* CA profiles can issue certs and sign CRLS */
        set_extension(ca.cert, cert, NID_basic_constraints, "critical,CA:TRUE");
        set_extension(ca.cert, cert, NID_key_usage, "critical,keyCertSign,cRLSign");
        set_extension(ca.cert, cert, NID_subject_key_identifier, "hash");
        set_extension(ca.cert, cert, NID_authority_key_identifier, "keyid:always");
        break;

        case PROFILE_CLIENT:
        if (ci->email[0]) {
            printf("ret: %d\n", set_extension(ca.cert, cert, NID_subject_alt_name, ci->email));
        }
        set_extension(ca.cert, cert, NID_basic_constraints, "CA:FALSE");
        set_extension(ca.cert, cert, NID_netscape_comment, "Generated by 2CCA");
        set_extension(ca.cert, cert, NID_anyExtendedKeyUsage, "clientAuth");
        set_extension(ca.cert, cert, NID_key_usage, "digitalSignature");
        set_extension(ca.cert, cert, NID_subject_key_identifier, "hash");
        set_extension(ca.cert, cert, NID_authority_key_identifier, "issuer:always,keyid:always");
        break ;

        case PROFILE_SERVER:
        if (ci->email[0]) {
            printf("ret: %d\n", set_extension(ca.cert, cert, NID_subject_alt_name, ci->email));
        }
        set_extension(ca.cert, cert, NID_basic_constraints, "CA:FALSE");
        set_extension(ca.cert, cert, NID_netscape_comment, "Generated by 2CCA");
        set_extension(ca.cert, cert, NID_netscape_cert_type, "server");
        set_extension(ca.cert, cert, NID_anyExtendedKeyUsage, "serverAuth");
        set_extension(ca.cert, cert, NID_key_usage, "digitalSignature,keyEncipherment");
        set_extension(ca.cert, cert, NID_subject_key_identifier, "hash");
        set_extension(ca.cert, cert, NID_authority_key_identifier, "issuer:always,keyid:always");
        break ;

        case PROFILE_UNKNOWN:
        default:
        break ;
    }
    /* Set issuer */
    if (ci->profile==PROFILE_ROOT_CA) {
        /* Self-signed */
        X509_set_issuer_name(cert, name);
        X509_sign(cert, pkey, EVP_sha256());
    } else {
        /* Signed by parent CA */
        X509_set_issuer_name(cert, X509_get_subject_name(ca.cert));
        X509_sign(cert, ca.key, EVP_sha256());
    }

    printf("Saving results to %s.[crt|key]\n", ci->cn);
    pem = fopen(filename, "wb");
    PEM_write_PrivateKey(pem, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pem);
    sprintf(filename, "%s.crt", ci->cn);
    pem = fopen(filename, "wb");
    PEM_write_X509(pem, cert);
    fclose(pem);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    if (ci->profile!=PROFILE_ROOT_CA) {
        X509_free(ca.cert);
        EVP_PKEY_free(ca.key);
    }
    printf("done\n");

    return 0;
}

static X509_CRL * load_crl(char * ca_name)
{
    FILE * fp ;
    BIO  * in ;
    X509_CRL * crl ;
    char filename[FIELD_SZ+5];

    sprintf(filename, "%s.crl", ca_name);
    in = BIO_new(BIO_s_file());
    if ((fp=fopen(filename, "rb"))==NULL) {
        BIO_free(in);
        return NULL ;
    }
    BIO_set_fp(in, fp, BIO_NOCLOSE);
    crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    fclose(fp);
    BIO_free(in);
    return crl ;
}

/*
 * openssl crl -in ca.crl -text
 */
void show_crl(char * ca_name)
{
    X509_CRL * crl ;
    X509_REVOKED * rev ;
    int i, total ;
    STACK_OF(X509_REVOKED) * rev_list ;
    BIO * out ;

    if ((crl = load_crl(ca_name))==NULL) {
        printf("No CRL found\n");
        return ;
    }
    rev_list = X509_CRL_get_REVOKED(crl);
    total = sk_X509_REVOKED_num(rev_list);

    out = BIO_new(BIO_s_file());
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(out, "-- Revoked certificates found in CRL\n");
    for (i=0 ; i<total ; i++) {
        rev=sk_X509_REVOKED_value(rev_list, i);
        BIO_printf(out, "serial: ");
        i2a_ASN1_INTEGER(out, rev->serialNumber);
        BIO_printf(out, "\n  date: ");
        ASN1_TIME_print(out, rev->revocationDate);
        BIO_printf(out, "\n\n");
    }
    X509_CRL_free(crl);
    BIO_free_all(out);
    return ;
}

/*
 * Revoke one certificate at a time
 * No check performed to see if certificate already revoked.
 */
void revoke_cert(char * ca_name, char * name)
{
    char filename[FIELD_SZ+5];
    FILE * f ;
    X509_CRL * crl ;
    X509 * cert ;
    ASN1_INTEGER * r_serial ;
    ASN1_INTEGER * crlnum ;
    X509_REVOKED * rev ;
    ASN1_TIME * tm ;
    identity ca ;
    BIO * out ;
    BIGNUM * b_crlnum ;

    /* Find requested certificate by name */
    sprintf(filename, "%s.crt", name);
    if ((f=fopen(filename, "r"))==NULL) {
        fprintf(stderr, "Cannot find: %s\n", filename);
        return ; 
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    /* Get certificate serial number */
    r_serial = X509_get_serialNumber(cert);

    /* Find out if if was already revoked */

    /* Make a revoked object with that serial */
    rev = X509_REVOKED_new();
    X509_REVOKED_set_serialNumber(rev, r_serial);
    X509_free(cert);
    /* Set reason to unspecified */
    rev->reason = ASN1_ENUMERATED_get(CRL_REASON_UNSPECIFIED);

    /* Load or create new CRL */
    if ((crl = load_crl(ca_name))==NULL) {
        crl = X509_CRL_new();
        X509_CRL_set_version(crl, 1);
        /* Set CRL number */
        crlnum = ASN1_INTEGER_new();
        ASN1_INTEGER_set(crlnum, 1);
        X509_CRL_add1_ext_i2d(crl, NID_crl_number, crlnum, 0, 0);
        ASN1_INTEGER_free(crlnum);
    } else {
        crlnum = X509_CRL_get_ext_d2i(crl, NID_crl_number, 0, 0);
        b_crlnum = ASN1_INTEGER_to_BN(crlnum, NULL);
        BN_add_word(b_crlnum, 1);
        BN_to_ASN1_INTEGER(b_crlnum, crlnum);
        BN_free(b_crlnum);
        X509_CRL_add1_ext_i2d(crl, NID_crl_number, crlnum, 0, X509V3_ADD_REPLACE_EXISTING);
        ASN1_INTEGER_free(crlnum);
    }

    /* What time is it? */
    tm = ASN1_TIME_new();
    X509_gmtime_adj(tm, 0);
    X509_REVOKED_set_revocationDate(rev, tm);
    X509_CRL_set_lastUpdate(crl, tm);

    /* Set CRL next update to a year from now */
    X509_gmtime_adj(tm, 365*24*60*60);
    X509_CRL_set_nextUpdate(crl, tm);
    ASN1_TIME_free(tm);

    /* Add revoked to CRL */
    X509_CRL_add0_revoked(crl, rev);    
    X509_CRL_sort(crl);

    /* Load root key to sign CRL */
    if (load_ca(ca_name, &ca)!=0) {
        fprintf(stderr, "Cannot find CA key/crt\n");
        return ;
    }
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca.cert));
    X509_free(ca.cert);

    /* Sign CRL */
    X509_CRL_sign(crl, ca.key, EVP_sha256());
    EVP_PKEY_free(ca.key);

    /* Dump CRL */
    if ((f = fopen("ca.crl", "wb"))==NULL) {
        fprintf(stderr, "Cannot write ca.crl: aborting\n");
        X509_CRL_free(crl);
        return ;
    }
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out, f, BIO_NOCLOSE);
    PEM_write_bio_X509_CRL(out, crl);
    BIO_free_all(out);
    fclose(f);
    X509_CRL_free(crl);
    return ;
}

int generate_dhparam(int dh_bits)
{
    DH * dh ;
    char filename[FIELD_SZ+1];
    FILE * out;

    sprintf(filename, "dh%d.pem", dh_bits);
    if ((out=fopen(filename, "wb"))==NULL) {
        fprintf(stderr, "Cannot create %s: aborting\n", filename);
        return -1;
    }
    dh = DH_new();
    printf("Generating DH parameters (%d bits) -- this can take long\n", dh_bits);
    DH_generate_parameters_ex(dh, dh_bits, DH_GENERATOR_2, 0);
    PEM_write_DHparams(out, dh);
    fclose(out);
    printf("done\n");
    return 0;
}

void usage(void)
{
    printf(
        "\n"
        "\tUse:\n"
        "\t2cca root   [DN] [duration=xx]         # Create a root CA\n"
        "\t2cca sub    [DN] [duration=xx] [ca=xx] # Create a sub CA\n"
        "\t2cca server [DN] [duration=xx] [ca=xx] # Create a server\n"
        "\t2cca client [DN] [duration=xx] [ca=xx] # Create a client\n"
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
        "\tCertificate duration in days\n"
        "\tSigning CA is specified with ca=CN (default: root)\n"
        "\n"
        "\t2cca crl [ca=xx]            # Show CRL for CA xx\n"
        "\t2cca revoke NAME [ca=xx]    # Revoke single cert by name\n"
        "\n"
        "\t2cca dh [numbits]           # Generate DH parameters\n"
        "\n"
    );
}

int parse_cmd_line(int argc, char ** argv, certinfo *ci)
{
    int i ;
    char key[FIELD_SZ] ;
    char val[FIELD_SZ] ;

    for (i=2 ; i<argc ; i++) { 
        if (sscanf(argv[i], "%[^=]=%s", key, val)==2) {
            if (!strcmp(key, "O")) {
                strcpy(ci->o, val);
            } else if (!strcmp(key, "C")) {
                strcpy(ci->c, val);
            } else if (!strcmp(key, "ST")) {
                strcpy(ci->st, val);
            } else if (!strcmp(key, "CN")) {
                strcpy(ci->cn, val);
            } else if (!strcmp(key, "L")) {
                strcpy(ci->l, val);
            } else if (!strcmp(key, "email")) {
                sprintf(ci->email, "email:%s", val);
            } else if (!strcmp(key, "duration")) {
                ci->duration = atoi(val);
            } else if (!strcmp(key, "ca")) {
                strcpy(ci->signing_ca, val);
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
    certinfo ci ;
    int      dh_bits=2048;

	if (argc<2) {
        usage();
		return 1 ;
	}

    OpenSSL_add_all_algorithms();

    /* Initialize DN fields to default values */
    memset(&ci, 0, sizeof(certinfo));
    strcpy(ci.o, "Home");
    strcpy(ci.c, "ZZ");
    ci.duration = 3650 ;
    strcpy(ci.signing_ca, "root");

    if ((argc>2) && (parse_cmd_line(argc, argv, &ci)!=0)) {
        return -1 ;
    }

    if (ci.cn[0]==0) {
        strcpy(ci.cn, argv[1]);
    }

    if (!strcmp(argv[1], "root")) {
        ci.profile = PROFILE_ROOT_CA ;
        build_identity(&ci);
    } else if (!strcmp(argv[1], "sub")) {
        ci.profile = PROFILE_SUB_CA ;
        build_identity(&ci);
    } else if (!strcmp(argv[1], "server")) {
        ci.profile = PROFILE_SERVER ;
        build_identity(&ci) ;
    } else if (!strcmp(argv[1], "client")) {
        ci.profile = PROFILE_CLIENT ;
        build_identity(&ci) ;
    } else if (!strcmp(argv[1], "crl")) {
        show_crl(ci.signing_ca);
    } else if (!strcmp(argv[1], "revoke")) {
        if (argc>2) {
            revoke_cert(ci.signing_ca, argv[2]);
        } else {
            fprintf(stderr, "Missing certificate name for revocation\n");
        }
    } else if (!strcmp(argv[1], "dh")) {
        if (argc>2) {
            dh_bits=atoi(argv[2]);
        }
        generate_dhparam(dh_bits);
    }
	return 0 ;
}

