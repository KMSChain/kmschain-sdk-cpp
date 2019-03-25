/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_x509parse.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/main_test.function
 *      Helper file     : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/helpers.function
 *      Test suite file : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function
 *      Test suite data : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.data
 *
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif


/*----------------------------------------------------------------------------*/
/* Common helper code */

#line 1 "helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif

/*----------------------------------------------------------------------------*/
/* Constants */

#define DEPENDENCY_SUPPORTED        0
#define DEPENDENCY_NOT_SUPPORTED    1

#define KEY_VALUE_MAPPING_FOUND     0
#define KEY_VALUE_MAPPING_NOT_FOUND -1

#define DISPATCH_TEST_SUCCESS       0
#define DISPATCH_TEST_FN_NOT_FOUND  1
#define DISPATCH_INVALID_TEST_DATA  2
#define DISPATCH_UNSUPPORTED_SUITE  3


/*----------------------------------------------------------------------------*/
/* Macros */

#define TEST_ASSERT( TEST )                         \
    do {                                            \
        if( ! (TEST) )                              \
        {                                           \
            test_fail( #TEST, __LINE__, __FILE__ ); \
            goto exit;                              \
        }                                           \
    } while( 0 )

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */


static struct
{
    int failed;
    const char *test;
    const char *filename;
    int line_no;
}
test_info;


/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * Allocate and zeroize a buffer.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *zero_alloc( size_t len )
{
    void *p;
    size_t actual_len = ( len != 0 ) ? len : 1;

    p = mbedtls_calloc( 1, actual_len );
    assert( p != NULL );

    memset( p, 0x00, actual_len );

    return( p );
}

/**
 * Allocate and fill a buffer from hex data.
 *
 * The buffer is sized exactly as needed. This allows to detect buffer
 * overruns (including overreads) when running the test suite under valgrind.
 *
 * If the size if zero, a pointer to a zeroized 1-byte buffer is returned.
 *
 * For convenience, dies if allocation fails.
 */
static unsigned char *unhexify_alloc( const char *ibuf, size_t *olen )
{
    unsigned char *obuf;

    *olen = strlen( ibuf ) / 2;

    if( *olen == 0 )
        return( zero_alloc( *olen ) );

    obuf = mbedtls_calloc( 1, *olen );
    assert( obuf != NULL );

    (void) unhexify( obuf, ibuf );

    return( obuf );
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 *
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += ( ( ( info->v1 << 4 ) ^ ( info->v1 >> 5 ) )
                            + info->v1 ) ^ ( sum + k[sum & 3] );
            sum += delta;
            info->v1 += ( ( ( info->v0 << 4 ) ^ ( info->v0 >> 5 ) )
                            + info->v0 ) ^ ( sum + k[( sum>>11 ) & 3] );
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}

static void test_fail( const char *test, int line_no, const char* filename )
{
    test_info.failed = 1;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}



/*----------------------------------------------------------------------------*/
/* Test Suite Code */

#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pem.h"
#include "mbedtls/oid.h"
#include "mbedtls/base64.h"

#if MBEDTLS_X509_MAX_INTERMEDIATE_CA > 19
#error "The value of MBEDTLS_X509_MAX_INTERMEDIATE_C is larger \
than the current threshold 19. To test larger values, please \
adapt the script tests/data_files/dir-max/long.sh."
#endif

/* Profile for backward compatibility. Allows SHA-1, unlike the default
   profile. */
const mbedtls_x509_crt_profile compat_profile =
{
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_RIPEMD160 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1024,
};

const mbedtls_x509_crt_profile profile_rsa3072 =
{
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_RSA ),
    0,
    3072,
};

const mbedtls_x509_crt_profile profile_sha512 =
{
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1024,
};

int verify_none( void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags |= MBEDTLS_X509_BADCERT_OTHER;

    return 0;
}

int verify_all( void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags )
{
    ((void) data);
    ((void) crt);
    ((void) certificate_depth);
    *flags = 0;

    return 0;
}

int verify_fatal( void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags )
{
    int *levels = (int *) data;

    ((void) crt);
    ((void) certificate_depth);

    /* Simulate a fatal error in the callback */
    if( *levels & ( 1 << certificate_depth ) )
    {
        *flags |= ( 1 << certificate_depth );
        return( -1 - certificate_depth );
    }

    return( 0 );
}

/* strsep() not available on Windows */
char *mystrsep(char **stringp, const char *delim)
{
    const char *p;
    char *ret = *stringp;

    if( *stringp == NULL )
        return( NULL );

    for( ; ; (*stringp)++ )
    {
        if( **stringp == '\0' )
        {
            *stringp = NULL;
            goto done;
        }

        for( p = delim; *p != '\0'; p++ )
            if( **stringp == *p )
            {
                **stringp = '\0';
                (*stringp)++;
                goto done;
            }
    }

done:
    return( ret );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
typedef struct {
    char buf[512];
    char *p;
} verify_print_context;

void verify_print_init( verify_print_context *ctx )
{
    memset( ctx, 0, sizeof( verify_print_context ) );
    ctx->p = ctx->buf;
}

int verify_print( void *data, mbedtls_x509_crt *crt, int certificate_depth, uint32_t *flags )
{
    int ret;
    verify_print_context *ctx = (verify_print_context *) data;
    char *p = ctx->p;
    size_t n = ctx->buf + sizeof( ctx->buf ) - ctx->p;
    ((void) flags);

    ret = mbedtls_snprintf( p, n, "depth %d - serial ", certificate_depth );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_serial_gets( p, n, &crt->serial );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, " - subject " );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_dn_gets( p, n, &crt->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, " - flags 0x%08x\n", *flags );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ctx->p = p;

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_BIGNUM_C)

#define TEST_SUITE_ACTIVE

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCRL_BAD_MD | MBEDTLS_X509_BADCERT_BAD_MD" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCRL_BAD_MD | MBEDTLS_X509_BADCERT_BAD_MD );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "-3" ) == 0 )
    {
        *value = ( -3 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCRL_NOT_TRUSTED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCRL_NOT_TRUSTED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_FUTURE" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_FUTURE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED|MBEDTLS_X509_BADCRL_FUTURE" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED|MBEDTLS_X509_BADCRL_FUTURE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_ASN1_INVALID_LENGTH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCRL_FUTURE" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCRL_FUTURE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ASN1_CONTEXT_SPECIFIC" ) == 0 )
    {
        *value = ( MBEDTLS_ASN1_CONTEXT_SPECIFIC );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_OTHER | 0x80000000" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_OTHER | 0x80000000 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_INVALID_LENGTH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_DECIPHER_ONLY" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_DECIPHER_ONLY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCRL_EXPIRED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SERIAL + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME+MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "-1" ) == 0 )
    {
        *value = ( -1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCRL_BAD_MD" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCRL_BAD_MD );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_PUBKEY" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_PUBKEY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_NOT_TRUSTED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_NOT_TRUSTED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_KEY" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_KEY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_VERSION" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "-4" ) == 0 )
    {
        *value = ( -4 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_INVALID_LENGTH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
    if( strcmp( str, "MBEDTLS_ERR_PEM_INVALID_DATA + MBEDTLS_ERR_BASE64_INVALID_CHARACTER" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PEM_INVALID_DATA + MBEDTLS_ERR_BASE64_INVALID_CHARACTER );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_FS_IO
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY|MBEDTLS_X509_BADCRL_BAD_MD|MBEDTLS_X509_BADCRL_BAD_PK" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY|MBEDTLS_X509_BADCRL_BAD_MD|MBEDTLS_X509_BADCRL_BAD_PK );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_MD|MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_MAX_INTERMEDIATE_CA-1" ) == 0 )
    {
        *value = ( MBEDTLS_X509_MAX_INTERMEDIATE_CA-1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_KEY_CERT_SIGN|MBEDTLS_X509_KU_CRL_SIGN" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_KEY_CERT_SIGN|MBEDTLS_X509_KU_CRL_SIGN );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_OTHER" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_OTHER );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ERR_OID_BUF_TOO_SMALL" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_OID_BUF_TOO_SMALL );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE + MBEDTLS_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE + MBEDTLS_ERR_OID_NOT_FOUND );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ASN1_UTC_TIME" ) == 0 )
    {
        *value = ( MBEDTLS_ASN1_UTC_TIME );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_CN_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_PK" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_PK );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_PK" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_PK );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_DIGITAL_SIGNATURE" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_DIGITAL_SIGNATURE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_ASN1_INVALID_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_CN_MISMATCH + MBEDTLS_X509_BADCERT_NOT_TRUSTED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_CN_MISMATCH + MBEDTLS_X509_BADCERT_NOT_TRUSTED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_KEY_AGREEMENT" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_KEY_ENCIPHERMENT|MBEDTLS_X509_KU_KEY_AGREEMENT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_ERR_X509_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
    if( strcmp( str, "MBEDTLS_ERR_X509_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_SIG_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_SIG_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_SIG_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_INVALID_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_OID_NOT_FOUND" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_ALG + MBEDTLS_ERR_OID_NOT_FOUND );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_FATAL_ERROR" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_FATAL_ERROR );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE" ) == 0 )
    {
        *value = ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_MAX_INTERMEDIATE_CA" ) == 0 )
    {
        *value = ( MBEDTLS_X509_MAX_INTERMEDIATE_CA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_UNKNOWN_PK_ALG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_NAME + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED | MBEDTLS_X509_BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_EXPIRED | MBEDTLS_X509_BADCERT_CN_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_EXPIRED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_EXPIRED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_BAD_PK|MBEDTLS_X509_BADCERT_BAD_KEY );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_INVALID_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_INVALID_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE | MBEDTLS_X509_BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE | MBEDTLS_X509_BADCERT_CN_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_MD_SHA256" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA256 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_MAX_INTERMEDIATE_CA+1" ) == 0 )
    {
        *value = ( MBEDTLS_X509_MAX_INTERMEDIATE_CA+1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_SIGNATURE + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "-2" ) == 0 )
    {
        *value = ( -2 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_DATE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_DATE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_USE_C
    if( strcmp( str, "MBEDTLS_ASN1_GENERALIZED_TIME" ) == 0 )
    {
        *value = ( MBEDTLS_ASN1_GENERALIZED_TIME );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_USE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCRL_FUTURE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCRL_EXPIRED" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCRL_EXPIRED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_INVALID_LENGTH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_INVALID_LENGTH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_CERT_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_CERT_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
    if( strcmp( str, "MBEDTLS_X509_KU_KEY_CERT_SIGN" ) == 0 )
    {
        *value = ( MBEDTLS_X509_KU_KEY_CERT_SIGN );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_FS_IO
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_CHECK_KEY_USAGE
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
    if( strcmp( str, "MBEDTLS_ASN1_SEQUENCE" ) == 0 )
    {
        *value = ( MBEDTLS_ASN1_SEQUENCE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#endif // MBEDTLS_X509_RSASSA_PSS_SUPPORT
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_X509_BADCERT_MISSING" ) == 0 )
    {
        *value = ( MBEDTLS_X509_BADCERT_MISSING );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CSR_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CSR_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRL_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_FORMAT + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRT_PARSE_C
    if( strcmp( str, "MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_X509_INVALID_VERSION + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_X509_CRT_PARSE_C


    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 164 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_cert_info( char *crt_file, char *result_str )
{
    mbedtls_x509_crt   crt;
    char buf[2000];
    int res;

    mbedtls_x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );
    res = mbedtls_x509_crt_info( buf, 2000, "", &crt );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRL_PARSE_C
#line 187 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_crl_info( char *crl_file, char *result_str )
{
    mbedtls_x509_crl   crl;
    char buf[2000];
    int res;

    mbedtls_x509_crl_init( &crl );
    memset( buf, 0, 2000 );

    TEST_ASSERT( mbedtls_x509_crl_parse_file( &crl, crl_file ) == 0 );
    res = mbedtls_x509_crl_info( buf, 2000, "", &crl );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    mbedtls_x509_crl_free( &crl );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRL_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRL_PARSE_C
#line 210 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_crl_parse( char *crl_file, int result )
{
    mbedtls_x509_crl   crl;
    char buf[2000];

    mbedtls_x509_crl_init( &crl );
    memset( buf, 0, 2000 );

    TEST_ASSERT( mbedtls_x509_crl_parse_file( &crl, crl_file ) == result );

exit:
    mbedtls_x509_crl_free( &crl );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRL_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CSR_PARSE_C
#line 226 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_csr_info( char *csr_file, char *result_str )
{
    mbedtls_x509_csr   csr;
    char buf[2000];
    int res;

    mbedtls_x509_csr_init( &csr );
    memset( buf, 0, 2000 );

    TEST_ASSERT( mbedtls_x509_csr_parse_file( &csr, csr_file ) == 0 );
    res = mbedtls_x509_csr_info( buf, 2000, "", &csr );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    mbedtls_x509_csr_free( &csr );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 249 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_verify_info( int flags, char *prefix, char *result_str )
{
    char buf[2000];
    int res;

    memset( buf, 0, sizeof( buf ) );

    res = mbedtls_x509_crt_verify_info( buf, sizeof( buf ), prefix, flags );

    TEST_ASSERT( res >= 0 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CRL_PARSE_C
#line 265 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_verify( char *crt_file, char *ca_file, char *crl_file,
                  char *cn_name_str, int result, int flags_result,
                  char *profile_str,
                  char *verify_callback )
{
    mbedtls_x509_crt   crt;
    mbedtls_x509_crt   ca;
    mbedtls_x509_crl    crl;
    uint32_t         flags = 0;
    int         res;
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *) = NULL;
    char *      cn_name = NULL;
    const mbedtls_x509_crt_profile *profile;

    mbedtls_x509_crt_init( &crt );
    mbedtls_x509_crt_init( &ca );
    mbedtls_x509_crl_init( &crl );

    if( strcmp( cn_name_str, "NULL" ) != 0 )
        cn_name = cn_name_str;

    if( strcmp( profile_str, "" ) == 0 )
        profile = &mbedtls_x509_crt_profile_default;
    else if( strcmp( profile_str, "next" ) == 0 )
        profile = &mbedtls_x509_crt_profile_next;
    else if( strcmp( profile_str, "suite_b" ) == 0 )
        profile = &mbedtls_x509_crt_profile_suiteb;
    else if( strcmp( profile_str, "compat" ) == 0 )
        profile = &compat_profile;
    else
        TEST_ASSERT( "Unknown algorithm profile" == 0 );

    if( strcmp( verify_callback, "NULL" ) == 0 )
        f_vrfy = NULL;
    else if( strcmp( verify_callback, "verify_none" ) == 0 )
        f_vrfy = verify_none;
    else if( strcmp( verify_callback, "verify_all" ) == 0 )
        f_vrfy = verify_all;
    else
        TEST_ASSERT( "No known verify callback selected" == 0 );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );
    TEST_ASSERT( mbedtls_x509_crt_parse_file( &ca, ca_file ) == 0 );
    TEST_ASSERT( mbedtls_x509_crl_parse_file( &crl, crl_file ) == 0 );

    res = mbedtls_x509_crt_verify_with_profile( &crt, &ca, &crl, profile, cn_name, &flags, f_vrfy, NULL );

    TEST_ASSERT( res == ( result ) );
    TEST_ASSERT( flags == (uint32_t)( flags_result ) );

exit:
    mbedtls_x509_crt_free( &crt );
    mbedtls_x509_crt_free( &ca );
    mbedtls_x509_crl_free( &crl );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_X509_CRL_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 323 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_verify_callback( char *crt_file, char *ca_file, char *name,
                           int exp_ret, char *exp_vrfy_out )
{
    int ret;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt ca;
    uint32_t flags = 0;
    verify_print_context vrfy_ctx;

    mbedtls_x509_crt_init( &crt );
    mbedtls_x509_crt_init( &ca );
    verify_print_init( &vrfy_ctx );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );
    TEST_ASSERT( mbedtls_x509_crt_parse_file( &ca, ca_file ) == 0 );

    if( strcmp( name, "NULL" ) == 0 )
        name = NULL;

    ret = mbedtls_x509_crt_verify_with_profile( &crt, &ca, NULL,
                                                &compat_profile,
                                                name, &flags,
                                                verify_print, &vrfy_ctx );

    TEST_ASSERT( ret == exp_ret );
    TEST_ASSERT( strcmp( vrfy_ctx.buf, exp_vrfy_out ) == 0 );

exit:
    mbedtls_x509_crt_free( &crt );
    mbedtls_x509_crt_free( &ca );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 357 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_dn_gets( char *crt_file, char *entity, char *result_str )
{
    mbedtls_x509_crt   crt;
    char buf[2000];
    int res = 0;

    mbedtls_x509_crt_init( &crt );
    memset( buf, 0, 2000 );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );
    if( strcmp( entity, "subject" ) == 0 )
        res =  mbedtls_x509_dn_gets( buf, 2000, &crt.subject );
    else if( strcmp( entity, "issuer" ) == 0 )
        res =  mbedtls_x509_dn_gets( buf, 2000, &crt.issuer );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

    TEST_ASSERT( res != -1 );
    TEST_ASSERT( res != -2 );

    TEST_ASSERT( strcmp( buf, result_str ) == 0 );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 385 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_time_is_past( char *crt_file, char *entity, int result )
{
    mbedtls_x509_crt   crt;

    mbedtls_x509_crt_init( &crt );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );

    if( strcmp( entity, "valid_from" ) == 0 )
        TEST_ASSERT( mbedtls_x509_time_is_past( &crt.valid_from ) == result );
    else if( strcmp( entity, "valid_to" ) == 0 )
        TEST_ASSERT( mbedtls_x509_time_is_past( &crt.valid_to ) == result );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 406 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_time_is_future( char *crt_file, char *entity, int result )
{
    mbedtls_x509_crt   crt;

    mbedtls_x509_crt_init( &crt );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );

    if( strcmp( entity, "valid_from" ) == 0 )
        TEST_ASSERT( mbedtls_x509_time_is_future( &crt.valid_from ) == result );
    else if( strcmp( entity, "valid_to" ) == 0 )
        TEST_ASSERT( mbedtls_x509_time_is_future( &crt.valid_to ) == result );
    else
        TEST_ASSERT( "Unknown entity" == 0 );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_FS_IO
#line 427 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509parse_crt_file( char *crt_file, int result )
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init( &crt );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == result );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_FS_IO */

#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 441 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509parse_crt( char *crt_data, char *result_str, int result )
{
    mbedtls_x509_crt   crt;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    mbedtls_x509_crt_init( &crt );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crt_data );

    TEST_ASSERT( mbedtls_x509_crt_parse( &crt, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = mbedtls_x509_crt_info( (char *) output, 2000, "", &crt );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_X509_CRL_PARSE_C
#line 471 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509parse_crl( char *crl_data, char *result_str, int result )
{
    mbedtls_x509_crl   crl;
    unsigned char buf[2000];
    unsigned char output[2000];
    int data_len, res;

    mbedtls_x509_crl_init( &crl );
    memset( buf, 0, 2000 );
    memset( output, 0, 2000 );

    data_len = unhexify( buf, crl_data );

    TEST_ASSERT( mbedtls_x509_crl_parse( &crl, buf, data_len ) == ( result ) );
    if( ( result ) == 0 )
    {
        res = mbedtls_x509_crl_info( (char *) output, 2000, "", &crl );

        TEST_ASSERT( res != -1 );
        TEST_ASSERT( res != -2 );

        TEST_ASSERT( strcmp( (char *) output, result_str ) == 0 );
    }

exit:
    mbedtls_x509_crl_free( &crl );
}
#endif /* MBEDTLS_X509_CRL_PARSE_C */

#ifdef MBEDTLS_X509_CSR_PARSE_C
#line 501 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_csr_parse( char *csr_der_hex, char *ref_out, int ref_ret )
{
    mbedtls_x509_csr csr;
    unsigned char *csr_der = NULL;
    char my_out[1000];
    size_t csr_der_len;
    int my_ret;

    mbedtls_x509_csr_init( &csr );
    memset( my_out, 0, sizeof( my_out ) );
    csr_der = unhexify_alloc( csr_der_hex, &csr_der_len );

    my_ret = mbedtls_x509_csr_parse_der( &csr, csr_der, csr_der_len );
    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        size_t my_out_len = mbedtls_x509_csr_info( my_out, sizeof( my_out ), "", &csr );
        TEST_ASSERT( my_out_len == strlen( ref_out ) );
        TEST_ASSERT( strcmp( my_out, ref_out ) == 0 );
    }

exit:
    mbedtls_x509_csr_free( &csr );
    mbedtls_free( csr_der );
}
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 530 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_crt_parse_path( char *crt_path, int ret, int nb_crt )
{
    mbedtls_x509_crt chain, *cur;
    int i;

    mbedtls_x509_crt_init( &chain );

    TEST_ASSERT( mbedtls_x509_crt_parse_path( &chain, crt_path ) == ret );

    /* Check how many certs we got */
    for( i = 0, cur = &chain; cur != NULL; cur = cur->next )
        if( cur->raw.p != NULL )
            i++;

    TEST_ASSERT( i == nb_crt );

exit:
    mbedtls_x509_crt_free( &chain );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 552 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_crt_verify_max( char *ca_file, char *chain_dir, int nb_int,
                                  int ret_chk, int flags_chk )
{
    char file_buf[128];
    int ret;
    uint32_t flags;
    mbedtls_x509_crt trusted, chain;

    /*
     * We expect chain_dir to contain certificates 00.crt, 01.crt, etc.
     * with NN.crt signed by NN-1.crt
     */

    mbedtls_x509_crt_init( &trusted );
    mbedtls_x509_crt_init( &chain );

    /* Load trusted root */
    TEST_ASSERT( mbedtls_x509_crt_parse_file( &trusted, ca_file ) == 0 );

    /* Load a chain with nb_int intermediates (from 01 to nb_int),
     * plus one "end-entity" cert (nb_int + 1) */
    ret = mbedtls_snprintf( file_buf, sizeof file_buf, "%s/c%02d.pem", chain_dir,
                                                            nb_int + 1 );
    TEST_ASSERT( ret > 0 && (size_t) ret < sizeof file_buf );
    TEST_ASSERT( mbedtls_x509_crt_parse_file( &chain, file_buf ) == 0 );

    /* Try to verify that chain */
    ret = mbedtls_x509_crt_verify( &chain, &trusted, NULL, NULL, &flags,
                                   NULL, NULL );
    TEST_ASSERT( ret == ret_chk );
    TEST_ASSERT( flags == (uint32_t) flags_chk );

exit:
    mbedtls_x509_crt_free( &chain );
    mbedtls_x509_crt_free( &trusted );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#line 591 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_mbedtls_x509_crt_verify_chain(  char *chain_paths, char *trusted_ca,
                                     int flags_result, int result,
                                     char *profile_name, int vrfy_fatal_lvls )
{
    char* act;
    uint32_t flags;
    int res;
    mbedtls_x509_crt trusted, chain;
    const mbedtls_x509_crt_profile *profile = NULL;

    mbedtls_x509_crt_init( &chain );
    mbedtls_x509_crt_init( &trusted );

    while( ( act = mystrsep( &chain_paths, " " ) ) != NULL )
        TEST_ASSERT( mbedtls_x509_crt_parse_file( &chain, act ) == 0 );
    TEST_ASSERT( mbedtls_x509_crt_parse_file( &trusted, trusted_ca ) == 0 );

    if( strcmp( profile_name, "" ) == 0 )
        profile = &mbedtls_x509_crt_profile_default;
    else if( strcmp( profile_name, "next" ) == 0 )
        profile = &mbedtls_x509_crt_profile_next;
    else if( strcmp( profile_name, "suiteb" ) == 0 )
        profile = &mbedtls_x509_crt_profile_suiteb;
    else if( strcmp( profile_name, "rsa3072" ) == 0 )
        profile = &profile_rsa3072;
    else if( strcmp( profile_name, "sha512" ) == 0 )
        profile = &profile_sha512;

    res = mbedtls_x509_crt_verify_with_profile( &chain, &trusted, NULL, profile,
            NULL, &flags, verify_fatal, &vrfy_fatal_lvls );

    TEST_ASSERT( res == ( result ) );
    TEST_ASSERT( flags == (uint32_t)( flags_result ) );

exit:
    mbedtls_x509_crt_free( &trusted );
    mbedtls_x509_crt_free( &chain );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#ifdef MBEDTLS_X509_USE_C
#line 632 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_oid_desc( char *oid_str, char *ref_desc )
{
    mbedtls_x509_buf oid;
    const char *desc = NULL;
    unsigned char buf[20];
    int ret;

    memset( buf, 0, sizeof buf );

    oid.tag = MBEDTLS_ASN1_OID;
    oid.len = unhexify( buf, oid_str );
    oid.p   = buf;

    ret = mbedtls_oid_get_extended_key_usage( &oid, &desc );

    if( strcmp( ref_desc, "notfound" ) == 0 )
    {
        TEST_ASSERT( ret != 0 );
        TEST_ASSERT( desc == NULL );
    }
    else
    {
        TEST_ASSERT( ret == 0 );
        TEST_ASSERT( desc != NULL );
        TEST_ASSERT( strcmp( desc, ref_desc ) == 0 );
    }

exit:
    return;
}
#endif /* MBEDTLS_X509_USE_C */

#ifdef MBEDTLS_X509_USE_C
#line 662 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_oid_numstr( char *oid_str, char *numstr, int blen, int ret )
{
    mbedtls_x509_buf oid;
    unsigned char oid_buf[20];
    char num_buf[100];

    memset( oid_buf, 0x00, sizeof oid_buf );
    memset( num_buf, 0x2a, sizeof num_buf );

    oid.tag = MBEDTLS_ASN1_OID;
    oid.len = unhexify( oid_buf, oid_str );
    oid.p   = oid_buf;

    TEST_ASSERT( (size_t) blen <= sizeof num_buf );

    TEST_ASSERT( mbedtls_oid_get_numeric_string( num_buf, blen, &oid ) == ret );

    if( ret >= 0 )
    {
        TEST_ASSERT( num_buf[ret] == 0 );
        TEST_ASSERT( strcmp( num_buf, numstr ) == 0 );
    }

exit:
    return;
}
#endif /* MBEDTLS_X509_USE_C */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_KEY_USAGE
#line 688 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_check_key_usage( char *crt_file, int usage, int ret )
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init( &crt );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );

    TEST_ASSERT( mbedtls_x509_crt_check_key_usage( &crt, usage ) == ret );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_X509_CHECK_KEY_USAGE */

#ifdef MBEDTLS_FS_IO
#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#line 704 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_check_extended_key_usage( char *crt_file, char *usage_hex, int ret )
{
    mbedtls_x509_crt crt;
    char oid[50];
    size_t len;

    mbedtls_x509_crt_init( &crt );

    len = unhexify( (unsigned char *) oid, usage_hex );

    TEST_ASSERT( mbedtls_x509_crt_parse_file( &crt, crt_file ) == 0 );

    TEST_ASSERT( mbedtls_x509_crt_check_extended_key_usage( &crt, oid, len ) == ret );

exit:
    mbedtls_x509_crt_free( &crt );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

#ifdef MBEDTLS_X509_USE_C
#line 724 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_get_time( int tag,  char *time_str, int ret,
                    int year, int mon, int day,
                    int hour, int min, int sec )
{
    mbedtls_x509_time time;
    unsigned char buf[21];
    unsigned char* start = buf;
    unsigned char* end = buf;

    memset( &time, 0x00, sizeof( time ) );
    *end = (unsigned char)tag; end++;
    *end = strlen( time_str );
    TEST_ASSERT( *end < 20 );
    end++;
    memcpy( end, time_str, (size_t)*(end - 1) );
    end += *(end - 1);

    TEST_ASSERT( mbedtls_x509_get_time( &start, end, &time ) == ret );
    if( ret == 0 )
    {
        TEST_ASSERT( year == time.year );
        TEST_ASSERT( mon  == time.mon  );
        TEST_ASSERT( day  == time.day  );
        TEST_ASSERT( hour == time.hour );
        TEST_ASSERT( min  == time.min  );
        TEST_ASSERT( sec  == time.sec  );
    }

exit:
    return;
}
#endif /* MBEDTLS_X509_USE_C */

#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT
#line 755 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_parse_rsassa_pss_params( char *hex_params, int params_tag,
                                   int ref_msg_md, int ref_mgf_md,
                                   int ref_salt_len, int ref_ret )
{
    int my_ret;
    mbedtls_x509_buf params;
    mbedtls_md_type_t my_msg_md, my_mgf_md;
    int my_salt_len;

    params.p = unhexify_alloc( hex_params, &params.len );
    params.tag = params_tag;

    my_ret = mbedtls_x509_get_rsassa_pss_params( &params, &my_msg_md, &my_mgf_md,
                                         &my_salt_len );

    TEST_ASSERT( my_ret == ref_ret );

    if( ref_ret == 0 )
    {
        TEST_ASSERT( my_msg_md == (mbedtls_md_type_t) ref_msg_md );
        TEST_ASSERT( my_mgf_md == (mbedtls_md_type_t) ref_mgf_md );
        TEST_ASSERT( my_salt_len == ref_salt_len );
    }

exit:
    mbedtls_free( params.p );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

#ifdef MBEDTLS_X509_CRT_PARSE_C
#ifdef MBEDTLS_SELF_TEST
#line 785 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.function"
void test_suite_x509_selftest()
{
    TEST_ASSERT( mbedtls_x509_self_test( 1 ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#endif /* MBEDTLS_SELF_TEST */


#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 77 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "MBEDTLS_ECP_DP_SECP256R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP192R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_X509_RSASSA_PSS_SUPPORT" ) == 0 )
    {
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECDSA_C" ) == 0 )
    {
#if defined(MBEDTLS_ECDSA_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "!MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES" ) == 0 )
    {
#if !defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_MD2_C" ) == 0 )
    {
#if defined(MBEDTLS_MD2_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA256_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA256_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA1_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA1_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_PKCS1_V15" ) == 0 )
    {
#if defined(MBEDTLS_PKCS1_V15)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_SHA512_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA512_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_CERTS_C" ) == 0 )
    {
#if defined(MBEDTLS_CERTS_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_X509_CHECK_KEY_USAGE" ) == 0 )
    {
#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_MD5_C" ) == 0 )
    {
#if defined(MBEDTLS_MD5_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3" ) == 0 )
    {
#if defined(MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_RSA_C" ) == 0 )
    {
#if defined(MBEDTLS_RSA_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_HAVE_TIME_DATE" ) == 0 )
    {
#if defined(MBEDTLS_HAVE_TIME_DATE)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECP_DP_SECP384R1_ENABLED" ) == 0 )
    {
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES" ) == 0 )
    {
#if defined(MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_X509_USE_C" ) == 0 )
    {
#if defined(MBEDTLS_X509_USE_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_ECP_C" ) == 0 )
    {
#if defined(MBEDTLS_ECP_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_PEM_PARSE_C" ) == 0 )
    {
#if defined(MBEDTLS_PEM_PARSE_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }
    if( strcmp( str, "MBEDTLS_MD4_C" ) == 0 )
    {
#if defined(MBEDTLS_MD4_C)
        return( DEPENDENCY_SUPPORTED );
#else
        return( DEPENDENCY_NOT_SUPPORTED );
#endif
    }

#line 89 "main_test.function"

    return( DEPENDENCY_NOT_SUPPORTED );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    ret = DISPATCH_TEST_SUCCESS;

    // Cast to void to avoid compiler warnings
    (void)ret;

    if( strcmp( params[0], "x509_cert_info" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_cert_info( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_crl_info" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_crl_info( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRL_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_crl_parse" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRL_PARSE_C

        char *param1 = params[1];
        int param2;

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_crl_parse( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRL_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_csr_info" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CSR_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_csr_info( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CSR_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_verify_info" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        int param1;
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_verify_info( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_verify" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        int param5;
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];

        if( cnt != 9 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_verify( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_X509_CRL_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_verify_callback" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_verify_callback( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_dn_gets" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_dn_gets( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_time_is_past" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_time_is_past( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_time_is_future" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_time_is_future( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509parse_crt_file" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_FS_IO

        char *param1 = params[1];
        int param2;

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509parse_crt_file( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_FS_IO */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509parse_crt" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509parse_crt( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509parse_crl" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRL_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509parse_crl( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRL_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_csr_parse" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CSR_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_csr_parse( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CSR_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_crt_parse_path" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        int param2;
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_crt_parse_path( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_crt_verify_max" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_crt_verify_max( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_x509_crt_verify_chain" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_x509_crt_verify_chain( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_oid_desc" ) == 0 )
    {
    #ifdef MBEDTLS_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_oid_desc( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_USE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_oid_numstr" ) == 0 )
    {
    #ifdef MBEDTLS_X509_USE_C

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_oid_numstr( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_USE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_check_key_usage" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_X509_CHECK_KEY_USAGE

        char *param1 = params[1];
        int param2;
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_check_key_usage( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_X509_CHECK_KEY_USAGE */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_check_extended_key_usage" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_check_extended_key_usage( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_get_time" ) == 0 )
    {
    #ifdef MBEDTLS_X509_USE_C

        int param1;
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        int param6;
        int param7;
        int param8;
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_get_time( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_USE_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_parse_rsassa_pss_params" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_X509_RSASSA_PSS_SUPPORT

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        int param6;

        if( cnt != 7 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 7 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_x509_parse_rsassa_pss_params( param1, param2, param3, param4, param5, param6 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "x509_selftest" ) == 0 )
    {
    #ifdef MBEDTLS_X509_CRT_PARSE_C
    #ifdef MBEDTLS_SELF_TEST


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_x509_selftest(  );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_X509_CRT_PARSE_C */
    #endif /* MBEDTLS_SELF_TEST */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else

    {
#line 108 "main_test.function"
        mbedtls_fprintf( stdout,
                         "FAILED\nSkipping unknown test function '%s'\n",
                         params[0] );
        fflush( stdout );
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }
#else
    ret = DISPATCH_UNSUPPORTED_SUITE;
#endif
    return( ret );
}


/*----------------------------------------------------------------------------*/
/* Main Test code */

#line 125 "main_test.function"

#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data file. If no file is specified\n" \
    "                       the followimg default test case is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.data"


/** Retrieve one input line into buf, which must have room for len
 * bytes. The trailing line break (if any) is stripped from the result.
 * Lines beginning with the character '#' are skipped. Lines that are
 * more than len-1 bytes long including the trailing line break are
 * truncated; note that the following bytes remain in the input stream.
 *
 * \return 0 on success, -1 on error or end of file
 */
int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    do
    {
        ret = fgets( buf, len, f );
        if( ret == NULL )
            return( -1 );
    }
    while( buf[0] == '#' );

    ret = buf + strlen( buf );
    if( ret-- > buf && *ret == '\n' )
        *ret = '\0';
    if( ret-- > buf && *ret == '\r' )
        *ret = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

int main(int argc, const char *argv[])
{
    /* Local Configurations and options */
    const char *default_filename = "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_x509parse.data";
    const char *test_filename = NULL;
    const char **test_files = NULL;
    int testfile_count = 0;
    int option_verbose = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    int testfile_index, ret, i, cnt;
    int total_errors = 0, total_tests = 0, total_skipped = 0;
    FILE *file;
    char buf[5000];
    char *params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 0 );
    }

    while( arg_index < argc)
    {
        next_arg = argv[ arg_index ];

        if( strcmp(next_arg, "--verbose" ) == 0 ||
                 strcmp(next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }
        else
        {
            /* Not an option, therefore treat all further arguments as the file
             * list.
             */
            test_files = &argv[ arg_index ];
            testfile_count = argc - arg_index;
        }

        arg_index++;
    }

    /* If no files were specified, assume a default */
    if ( test_files == NULL || testfile_count == 0 )
    {
        test_files = &default_filename;
        testfile_count = 1;
    }

    /* Initialize the struct that holds information about the last test */
    memset( &test_info, 0, sizeof( test_info ) );

    /* Now begin to execute the tests in the testfiles */
    for ( testfile_index = 0;
          testfile_index < testfile_count;
          testfile_index++ )
    {
        int unmet_dep_count = 0;
        char *unmet_dependencies[20];

        test_filename = test_files[ testfile_index ];

        file = fopen( test_filename, "r" );
        if( file == NULL )
        {
            mbedtls_fprintf( stderr, "Failed to open test file: %s\n",
                             test_filename );
            return( 1 );
        }

        while( !feof( file ) )
        {
            if( unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stderr,
                    "FATAL: Dep count larger than zero at start of loop\n" );
                mbedtls_exit( MBEDTLS_EXIT_FAILURE );
            }
            unmet_dep_count = 0;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            mbedtls_fprintf( stdout, "%s%.66s", test_info.failed ? "\n" : "", buf );
            mbedtls_fprintf( stdout, " " );
            for( i = strlen( buf ) + 1; i < 67; i++ )
                mbedtls_fprintf( stdout, "." );
            mbedtls_fprintf( stdout, " " );
            fflush( stdout );

            total_tests++;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );

            if( strcmp( params[0], "depends_on" ) == 0 )
            {
                for( i = 1; i < cnt; i++ )
                {
                    if( dep_check( params[i] ) != DEPENDENCY_SUPPORTED )
                    {
                        if( 0 == option_verbose )
                        {
                            /* Only one count is needed if not verbose */
                            unmet_dep_count++;
                            break;
                        }

                        unmet_dependencies[ unmet_dep_count ] = strdup(params[i]);
                        if(  unmet_dependencies[ unmet_dep_count ] == NULL )
                        {
                            mbedtls_fprintf( stderr, "FATAL: Out of memory\n" );
                            mbedtls_exit( MBEDTLS_EXIT_FAILURE );
                        }
                        unmet_dep_count++;
                    }
                }

                if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                    break;
                cnt = parse_arguments( buf, strlen(buf), params );
            }

            // If there are no unmet dependencies execute the test
            if( unmet_dep_count == 0 )
            {
                test_info.failed = 0;

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                /* Suppress all output from the library unless we're verbose
                 * mode
                 */
                if( !option_verbose )
                {
                    stdout_fd = redirect_output( &stdout, "/dev/null" );
                    if( stdout_fd == -1 )
                    {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                    }
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

                ret = dispatch_test( cnt, params );

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
                if( !option_verbose && restore_output( &stdout, stdout_fd ) )
                {
                        /* Redirection has failed with no stdout so exit */
                        exit( 1 );
                }
#endif /* __unix__ || __APPLE__ __MACH__ */

            }

            if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                total_skipped++;
                mbedtls_fprintf( stdout, "----" );

                if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
                {
                    mbedtls_fprintf( stdout, "\n   Test Suite not enabled" );
                }

                if( 1 == option_verbose && unmet_dep_count > 0 )
                {
                    mbedtls_fprintf( stdout, "\n   Unmet dependencies: " );
                    for( i = 0; i < unmet_dep_count; i++ )
                    {
                        mbedtls_fprintf(stdout, "%s  ",
                                        unmet_dependencies[i]);
                        free(unmet_dependencies[i]);
                    }
                }
                mbedtls_fprintf( stdout, "\n" );
                fflush( stdout );

                unmet_dep_count = 0;
            }
            else if( ret == DISPATCH_TEST_SUCCESS )
            {
                if( test_info.failed == 0 )
                {
                    mbedtls_fprintf( stdout, "PASS\n" );
                }
                else
                {
                    total_errors++;
                    mbedtls_fprintf( stdout, "FAILED\n" );
                    mbedtls_fprintf( stdout, "  %s\n  at line %d, %s\n",
                                     test_info.test, test_info.line_no,
                                     test_info.filename );
                }
                fflush( stdout );
            }
            else if( ret == DISPATCH_INVALID_TEST_DATA )
            {
                mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
                fclose( file );
                mbedtls_exit( 2 );
            }
            else
                total_errors++;

            if( ( ret = get_line( file, buf, sizeof( buf ) ) ) != 0 )
                break;
            if( strlen( buf ) != 0 )
            {
                mbedtls_fprintf( stderr, "Should be empty %d\n",
                                 (int) strlen( buf ) );
                return( 1 );
            }
        }
        fclose( file );

        /* In case we encounter early end of file */
        for( i = 0; i < unmet_dep_count; i++ )
            free( unmet_dependencies[i] );
    }

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    if( stdout_fd != -1 )
        close_output( stdout );
#endif /* __unix__ || __APPLE__ __MACH__ */

    return( total_errors != 0 );
}

