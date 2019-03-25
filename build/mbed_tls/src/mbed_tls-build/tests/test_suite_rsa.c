/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_rsa.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/main_test.function
 *      Helper file     : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/helpers.function
 *      Test suite file : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function
 *      Test suite data : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.data
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

#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_GENPRIME)

#include "mbedtls/rsa.h"
#include "mbedtls/rsa_internal.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


#endif /* defined(MBEDTLS_RSA_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_GENPRIME) */


#line 1 "main_test.function"
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_BIGNUM_C)
#if defined(MBEDTLS_GENPRIME)

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

    if( strcmp( str, "MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_PRIVATE_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_MPI_NOT_ACCEPTABLE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_MD5" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD5 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA224" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA224 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_RSA_PKCS_V15" ) == 0 )
    {
        *value = ( MBEDTLS_RSA_PKCS_V15 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA384" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA384 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_INVALID_PADDING" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_INVALID_PADDING );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_MD4" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD4 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA256" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA256 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
    if( strcmp( str, "MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
#endif // MBEDTLS_CTR_DRBG_C
#endif // MBEDTLS_ENTROPY_C
    if( strcmp( str, "MBEDTLS_ERR_RSA_VERIFY_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_VERIFY_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA1" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA1 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_KEY_CHECK_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_MD2" ) == 0 )
    {
        *value = ( MBEDTLS_MD_MD2 );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_RNG_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_RNG_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_RSA_PUBLIC_FAILED + MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_MD_SHA512" ) == 0 )
    {
        *value = ( MBEDTLS_MD_SHA512 );
        return( KEY_VALUE_MAPPING_FOUND );
    }


    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 21 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_pkcs1_sign( char *message_hex_string, int padding_mode, int digest,
                     int mod, int radix_P, char *input_P, int radix_Q,
                     char *input_Q, int radix_N, char *input_N, int radix_E,
                     char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, P, Q, E;
    int msg_len;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P );
    mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, &P, &Q, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );
    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    if( mbedtls_md_info_from_type( digest ) != NULL )
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ),
                                 message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( mbedtls_rsa_pkcs1_sign( &ctx, &rnd_pseudo_rand, &rnd_info,
                                         MBEDTLS_RSA_PRIVATE, digest, 0,
                                         hash_result, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 79 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_pkcs1_verify( char *message_hex_string, int padding_mode, int digest,
                       int mod, int radix_N, char *input_N, int radix_E,
                       char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    mbedtls_rsa_context ctx;
    int msg_len;

    mbedtls_mpi N, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );
    unhexify( result_str, result_hex_str );

    if( mbedtls_md_info_from_type( digest ) != NULL )
        TEST_ASSERT( mbedtls_md( mbedtls_md_info_from_type( digest ), message_str, msg_len, hash_result ) == 0 );

    TEST_ASSERT( mbedtls_rsa_pkcs1_verify( &ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, digest, 0, hash_result, result_str ) == result );

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 119 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_pkcs1_sign_raw( char *message_hex_string, char *hash_result_string,
                         int padding_mode, int mod, int radix_P, char *input_P,
                         int radix_Q, char *input_Q, int radix_N,
                         char *input_N, int radix_E, char *input_E,
                         char *result_hex_str )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, P, Q, E;
    int hash_len;
    rnd_pseudo_info rnd_info;

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P );
    mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &E );

    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, &P, &Q, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );
    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    hash_len = unhexify( hash_result, hash_result_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_sign( &ctx, &rnd_pseudo_rand, &rnd_info,
                                         MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE,
                                         hash_len, hash_result, output ) == 0 );

    hexify( output_str, output, ctx.len );

    TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );

#if defined(MBEDTLS_PKCS1_V15)
    /* For PKCS#1 v1.5, there is an alternative way to generate signatures */
    if( padding_mode == MBEDTLS_RSA_PKCS_V15 )
    {
        int res;
        memset( output, 0x00, 1000 );
        memset( output_str, 0x00, 1000 );

        res = mbedtls_rsa_rsaes_pkcs1_v15_encrypt( &ctx,
                    &rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE,
                    hash_len, hash_result, output );

#if !defined(MBEDTLS_RSA_ALT)
        TEST_ASSERT( res == 0 );
#else
        TEST_ASSERT( ( res == 0 ) ||
                     ( res == MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION ) );
#endif

        if( res == 0 )
        {
            hexify( output_str, output, ctx.len );
            TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
        }
    }
#endif /* MBEDTLS_PKCS1_V15 */

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &E );

    mbedtls_rsa_free( &ctx );
}

#line 201 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_pkcs1_verify_raw( char *message_hex_string, char *hash_result_string,
                           int padding_mode, int mod, int radix_N,
                           char *input_N, int radix_E, char *input_E,
                           char *result_hex_str, int correct )
{
    unsigned char message_str[1000];
    unsigned char hash_result[1000];
    unsigned char result_str[1000];
    unsigned char output[1000];
    mbedtls_rsa_context ctx;
    size_t hash_len;

    mbedtls_mpi N, E;
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( hash_result, 0x00, 1000 );
    memset( result_str, 0x00, 1000 );
    memset( output, 0x00, sizeof( output ) );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    hash_len = unhexify( hash_result, hash_result_string );
    unhexify( result_str, result_hex_str );

    TEST_ASSERT( mbedtls_rsa_pkcs1_verify( &ctx, NULL, NULL,
                              MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE,
                              hash_len, hash_result,
                              result_str ) == correct );

#if defined(MBEDTLS_PKCS1_V15)
    /* For PKCS#1 v1.5, there is an alternative way to verify signatures */
    if( padding_mode == MBEDTLS_RSA_PKCS_V15 )
    {
        int res;
        int ok;
        size_t olen;

        res = mbedtls_rsa_rsaes_pkcs1_v15_decrypt( &ctx,
                    NULL, NULL, MBEDTLS_RSA_PUBLIC,
                    &olen, result_str, output, sizeof( output ) );

#if !defined(MBEDTLS_RSA_ALT)
        TEST_ASSERT( res == 0 );
#else
        TEST_ASSERT( ( res == 0 ) ||
                     ( res == MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION ) );
#endif

        if( res == 0 )
        {
            ok = olen == hash_len && memcmp( output, hash_result, olen ) == 0;
            if( correct == 0 )
                TEST_ASSERT( ok == 1 );
            else
                TEST_ASSERT( ok == 0 );
        }
    }
#endif /* MBEDTLS_PKCS1_V15 */

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 275 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_pkcs1_encrypt( char *message_hex_string, int padding_mode, int mod,
                        int radix_N, char *input_N, int radix_E, char *input_E,
                        char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    size_t msg_len;
    rnd_pseudo_info rnd_info;

    mbedtls_mpi N, E;
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );

    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_encrypt( &ctx, &rnd_pseudo_rand, &rnd_info,
                                            MBEDTLS_RSA_PUBLIC, msg_len,
                                            message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 322 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_pkcs1_encrypt_bad_rng( char *message_hex_string, int padding_mode,
                                int mod, int radix_N, char *input_N,
                                int radix_E, char *input_E,
                                char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    size_t msg_len;

    mbedtls_mpi N, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, padding_mode, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    msg_len = unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_pkcs1_encrypt( &ctx, &rnd_zero_rand, NULL,
                                            MBEDTLS_RSA_PUBLIC, msg_len,
                                            message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 367 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_pkcs1_decrypt( char *message_hex_string, int padding_mode, int mod,
                        int radix_P, char *input_P, int radix_Q, char *input_Q,
                        int radix_N, char *input_N, int radix_E, char *input_E,
                        int max_output, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx;
    size_t output_len;
    rnd_pseudo_info rnd_info;
    mbedtls_mpi N, P, Q, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P );
    mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &E );

    mbedtls_rsa_init( &ctx, padding_mode, 0 );

    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );


    TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, &P, &Q, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );
    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );
    output_len = 0;

    TEST_ASSERT( mbedtls_rsa_pkcs1_decrypt( &ctx, rnd_pseudo_rand, &rnd_info, MBEDTLS_RSA_PRIVATE, &output_len, message_str, output, max_output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strncasecmp( (char *) output_str, result_hex_str, strlen( result_hex_str ) ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 420 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_public( char *message_hex_string, int mod, int radix_N, char *input_N,
                 int radix_E, char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx, ctx2; /* Also test mbedtls_rsa_copy() while at it */

    mbedtls_mpi N, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &ctx2, MBEDTLS_RSA_PKCS_V15, 0 );
    memset( message_str, 0x00, 1000 );
    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );

    TEST_ASSERT( mbedtls_rsa_public( &ctx, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

    /* And now with the copy */
    TEST_ASSERT( mbedtls_rsa_copy( &ctx2, &ctx ) == 0 );
    /* clear the original to be sure */
    mbedtls_rsa_free( &ctx );

    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx2 ) == 0 );

    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    TEST_ASSERT( mbedtls_rsa_public( &ctx2, message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx2.len );

        TEST_ASSERT( strcasecmp( (char *) output_str, result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
    mbedtls_rsa_free( &ctx2 );
}

#line 479 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_private( char *message_hex_string, int mod, int radix_P, char *input_P,
                  int radix_Q, char *input_Q, int radix_N, char *input_N,
                  int radix_E, char *input_E, char *result_hex_str, int result )
{
    unsigned char message_str[1000];
    unsigned char output[1000];
    unsigned char output_str[1000];
    mbedtls_rsa_context ctx, ctx2; /* Also test mbedtls_rsa_copy() while at it */
    mbedtls_mpi N, P, Q, E;
    rnd_pseudo_info rnd_info;
    int i;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P );
    mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &ctx2, MBEDTLS_RSA_PKCS_V15, 0 );

    memset( message_str, 0x00, 1000 );
    memset( &rnd_info, 0, sizeof( rnd_pseudo_info ) );

    TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, &P, &Q, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_get_len( &ctx ) == (size_t) ( mod / 8 ) );
    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );
    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );

    unhexify( message_str, message_hex_string );

    /* repeat three times to test updating of blinding values */
    for( i = 0; i < 3; i++ )
    {
        memset( output, 0x00, 1000 );
        memset( output_str, 0x00, 1000 );
        TEST_ASSERT( mbedtls_rsa_private( &ctx, rnd_pseudo_rand, &rnd_info,
                                  message_str, output ) == result );
        if( result == 0 )
        {
            hexify( output_str, output, ctx.len );

            TEST_ASSERT( strcasecmp( (char *) output_str,
                                              result_hex_str ) == 0 );
        }
    }

    /* And now one more time with the copy */
    TEST_ASSERT( mbedtls_rsa_copy( &ctx2, &ctx ) == 0 );
    /* clear the original to be sure */
    mbedtls_rsa_free( &ctx );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx2 ) == 0 );

    memset( output, 0x00, 1000 );
    memset( output_str, 0x00, 1000 );
    TEST_ASSERT( mbedtls_rsa_private( &ctx2, rnd_pseudo_rand, &rnd_info,
                              message_str, output ) == result );
    if( result == 0 )
    {
        hexify( output_str, output, ctx2.len );

        TEST_ASSERT( strcasecmp( (char *) output_str,
                                          result_hex_str ) == 0 );
    }

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &E );

    mbedtls_rsa_free( &ctx ); mbedtls_rsa_free( &ctx2 );
}

#line 555 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_check_privkey_null()
{
    mbedtls_rsa_context ctx;
    memset( &ctx, 0x00, sizeof( mbedtls_rsa_context ) );

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

exit:
    return;
}

#line 565 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_check_pubkey( int radix_N, char *input_N, int radix_E, char *input_E,
                       int result )
{
    mbedtls_rsa_context ctx;
    mbedtls_mpi N, E;

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );

    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_import( &ctx, &N, NULL, NULL, NULL, &E ) == 0 );
    TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == result );

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
    mbedtls_rsa_free( &ctx );
}

#line 593 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_check_privkey( int mod, int radix_P, char *input_P, int radix_Q,
                        char *input_Q, int radix_N, char *input_N,
                        int radix_E, char *input_E, int radix_D, char *input_D,
                        int radix_DP, char *input_DP, int radix_DQ,
                        char *input_DQ, int radix_QP, char *input_QP,
                        int result )
{
    mbedtls_rsa_context ctx;

    mbedtls_rsa_init( &ctx, MBEDTLS_RSA_PKCS_V15, 0 );

    ctx.len = mod / 8;
    if( strlen( input_P ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.P, radix_P, input_P ) == 0 );
    }
    if( strlen( input_Q ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.Q, radix_Q, input_Q ) == 0 );
    }
    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.E, radix_E, input_E ) == 0 );
    }
    if( strlen( input_D ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.D, radix_D, input_D ) == 0 );
    }
#if !defined(MBEDTLS_RSA_NO_CRT)
    if( strlen( input_DP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.DP, radix_DP, input_DP ) == 0 );
    }
    if( strlen( input_DQ ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.DQ, radix_DQ, input_DQ ) == 0 );
    }
    if( strlen( input_QP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &ctx.QP, radix_QP, input_QP ) == 0 );
    }
#else
    ((void) radix_DP); ((void) input_DP);
    ((void) radix_DQ); ((void) input_DQ);
    ((void) radix_QP); ((void) input_QP);
#endif

    TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == result );

exit:
    mbedtls_rsa_free( &ctx );
}

#line 652 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_check_pubpriv( int mod, int radix_Npub, char *input_Npub,
                        int radix_Epub, char *input_Epub,
                        int radix_P, char *input_P, int radix_Q,
                        char *input_Q, int radix_N, char *input_N,
                        int radix_E, char *input_E, int radix_D, char *input_D,
                        int radix_DP, char *input_DP, int radix_DQ,
                        char *input_DQ, int radix_QP, char *input_QP,
                        int result )
{
    mbedtls_rsa_context pub, prv;

    mbedtls_rsa_init( &pub, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_rsa_init( &prv, MBEDTLS_RSA_PKCS_V15, 0 );

    pub.len = mod / 8;
    prv.len = mod / 8;

    if( strlen( input_Npub ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &pub.N, radix_Npub, input_Npub ) == 0 );
    }
    if( strlen( input_Epub ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &pub.E, radix_Epub, input_Epub ) == 0 );
    }

    if( strlen( input_P ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.P, radix_P, input_P ) == 0 );
    }
    if( strlen( input_Q ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.Q, radix_Q, input_Q ) == 0 );
    }
    if( strlen( input_N ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.N, radix_N, input_N ) == 0 );
    }
    if( strlen( input_E ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.E, radix_E, input_E ) == 0 );
    }
    if( strlen( input_D ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.D, radix_D, input_D ) == 0 );
    }
#if !defined(MBEDTLS_RSA_NO_CRT)
    if( strlen( input_DP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.DP, radix_DP, input_DP ) == 0 );
    }
    if( strlen( input_DQ ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.DQ, radix_DQ, input_DQ ) == 0 );
    }
    if( strlen( input_QP ) )
    {
        TEST_ASSERT( mbedtls_mpi_read_string( &prv.QP, radix_QP, input_QP ) == 0 );
    }
#else
    ((void) radix_DP); ((void) input_DP);
    ((void) radix_DQ); ((void) input_DQ);
    ((void) radix_QP); ((void) input_QP);
#endif

    TEST_ASSERT( mbedtls_rsa_check_pub_priv( &pub, &prv ) == result );

exit:
    mbedtls_rsa_free( &pub );
    mbedtls_rsa_free( &prv );
}

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
#ifdef ENTROPY_HAVE_STRONG
#line 726 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_gen_key( int nrbits, int exponent, int result)
{
    mbedtls_rsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "test_suite_rsa";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_rsa_init ( &ctx, 0, 0 );

    TEST_ASSERT( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) ) == 0 );

    TEST_ASSERT( mbedtls_rsa_gen_key( &ctx, mbedtls_ctr_drbg_random, &ctr_drbg, nrbits, exponent ) == result );
    if( result == 0 )
    {
        TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &ctx.P, &ctx.Q ) > 0 );
    }

exit:
    mbedtls_rsa_free( &ctx );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* ENTROPY_HAVE_STRONG */

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
#line 756 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_deduce_primes( int radix_N, char *input_N,
                                int radix_D, char *input_D,
                                int radix_E, char *input_E,
                                int radix_P, char *output_P,
                                int radix_Q, char *output_Q,
                                int corrupt, int result )
{
    mbedtls_mpi N, P, Pp, Q, Qp, D, E;

    mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &P );  mbedtls_mpi_init( &Q  );
    mbedtls_mpi_init( &Pp ); mbedtls_mpi_init( &Qp );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );

    TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &D, radix_D, input_D ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Qp, radix_P, output_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Pp, radix_Q, output_Q ) == 0 );

    if( corrupt )
        TEST_ASSERT( mbedtls_mpi_add_int( &D, &D, 2 ) == 0 );

    /* Try to deduce P, Q from N, D, E only. */
    TEST_ASSERT( mbedtls_rsa_deduce_primes( &N, &D, &E, &P, &Q ) == result );

    if( !corrupt )
    {
        /* Check if (P,Q) = (Pp, Qp) or (P,Q) = (Qp, Pp) */
        TEST_ASSERT( ( mbedtls_mpi_cmp_mpi( &P, &Pp ) == 0 && mbedtls_mpi_cmp_mpi( &Q, &Qp ) == 0 ) ||
                     ( mbedtls_mpi_cmp_mpi( &P, &Qp ) == 0 && mbedtls_mpi_cmp_mpi( &Q, &Pp ) == 0 ) );
    }

exit:
    mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &P  ); mbedtls_mpi_free( &Q  );
    mbedtls_mpi_free( &Pp ); mbedtls_mpi_free( &Qp );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */

#line 798 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_deduce_private_exponent( int radix_P, char *input_P,
                                          int radix_Q, char *input_Q,
                                          int radix_E, char *input_E,
                                          int radix_D, char *output_D,
                                          int corrupt, int result )
{
    mbedtls_mpi P, Q, D, Dp, E, R, Rp;

    mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &Dp );
    mbedtls_mpi_init( &E );
    mbedtls_mpi_init( &R ); mbedtls_mpi_init( &Rp );

    TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &Dp, radix_D, output_D ) == 0 );

    if( corrupt )
    {
        /* Make E even */
        TEST_ASSERT( mbedtls_mpi_set_bit( &E, 0, 0 ) == 0 );
    }

    /* Try to deduce D from N, P, Q, E. */
    TEST_ASSERT( mbedtls_rsa_deduce_private_exponent( &P, &Q,
                                                      &E, &D ) == result );

    if( !corrupt )
    {
        /*
         * Check that D and Dp agree modulo LCM(P-1, Q-1).
         */

        /* Replace P,Q by P-1, Q-1 */
        TEST_ASSERT( mbedtls_mpi_sub_int( &P, &P, 1 ) == 0 );
        TEST_ASSERT( mbedtls_mpi_sub_int( &Q, &Q, 1 ) == 0 );

        /* Check D == Dp modulo P-1 */
        TEST_ASSERT( mbedtls_mpi_mod_mpi( &R,  &D,  &P ) == 0 );
        TEST_ASSERT( mbedtls_mpi_mod_mpi( &Rp, &Dp, &P ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R,  &Rp )     == 0 );

        /* Check D == Dp modulo Q-1 */
        TEST_ASSERT( mbedtls_mpi_mod_mpi( &R,  &D,  &Q ) == 0 );
        TEST_ASSERT( mbedtls_mpi_mod_mpi( &Rp, &Dp, &Q ) == 0 );
        TEST_ASSERT( mbedtls_mpi_cmp_mpi( &R,  &Rp )     == 0 );
    }

exit:

    mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q  );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &Dp );
    mbedtls_mpi_free( &E );
    mbedtls_mpi_free( &R ); mbedtls_mpi_free( &Rp );
}

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
#ifdef ENTROPY_HAVE_STRONG
#line 857 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_import( int radix_N, char *input_N,
                         int radix_P, char *input_P,
                         int radix_Q, char *input_Q,
                         int radix_D, char *input_D,
                         int radix_E, char *input_E,
                         int successive,
                         int is_priv,
                         int res_check,
                         int res_complete )
{
    mbedtls_mpi N, P, Q, D, E;
    mbedtls_rsa_context ctx;

    /* Buffers used for encryption-decryption test */
    unsigned char *buf_orig = NULL;
    unsigned char *buf_enc  = NULL;
    unsigned char *buf_dec  = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "test_suite_rsa";

    const int have_N = ( strlen( input_N ) > 0 );
    const int have_P = ( strlen( input_P ) > 0 );
    const int have_Q = ( strlen( input_Q ) > 0 );
    const int have_D = ( strlen( input_D ) > 0 );
    const int have_E = ( strlen( input_E ) > 0 );

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_rsa_init( &ctx, 0, 0 );

    mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );

    TEST_ASSERT( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen( pers ) ) == 0 );

    if( have_N )
        TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );

    if( have_P )
        TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );

    if( have_Q )
        TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );

    if( have_D )
        TEST_ASSERT( mbedtls_mpi_read_string( &D, radix_D, input_D ) == 0 );

    if( have_E )
        TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    if( !successive )
    {
        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                             have_N ? &N : NULL,
                             have_P ? &P : NULL,
                             have_Q ? &Q : NULL,
                             have_D ? &D : NULL,
                             have_E ? &E : NULL ) == 0 );
    }
    else
    {
        /* Import N, P, Q, D, E separately.
         * This should make no functional difference. */

        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                               have_N ? &N : NULL,
                               NULL, NULL, NULL, NULL ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                               NULL,
                               have_P ? &P : NULL,
                               NULL, NULL, NULL ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                               NULL, NULL,
                               have_Q ? &Q : NULL,
                               NULL, NULL ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                               NULL, NULL, NULL,
                               have_D ? &D : NULL,
                               NULL ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import( &ctx,
                               NULL, NULL, NULL, NULL,
                               have_E ? &E : NULL ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == res_complete );

    /* On expected success, perform some public and private
     * key operations to check if the key is working properly. */
    if( res_complete == 0 )
    {
        if( is_priv )
            TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == res_check );
        else
            TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == res_check );

        if( res_check != 0 )
            goto exit;

        buf_orig = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        buf_enc  = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        buf_dec  = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        if( buf_orig == NULL || buf_enc == NULL || buf_dec == NULL )
            goto exit;

        TEST_ASSERT( mbedtls_ctr_drbg_random( &ctr_drbg,
                              buf_orig, mbedtls_rsa_get_len( &ctx ) ) == 0 );

        /* Make sure the number we're generating is smaller than the modulus */
        buf_orig[0] = 0x00;

        TEST_ASSERT( mbedtls_rsa_public( &ctx, buf_orig, buf_enc ) == 0 );

        if( is_priv )
        {
            TEST_ASSERT( mbedtls_rsa_private( &ctx, mbedtls_ctr_drbg_random,
                                              &ctr_drbg, buf_enc,
                                              buf_dec ) == 0 );

            TEST_ASSERT( memcmp( buf_orig, buf_dec,
                                 mbedtls_rsa_get_len( &ctx ) ) == 0 );
        }
    }

exit:

    mbedtls_free( buf_orig );
    mbedtls_free( buf_enc  );
    mbedtls_free( buf_dec  );

    mbedtls_rsa_free( &ctx );

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* ENTROPY_HAVE_STRONG */

#line 1006 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_export( int radix_N, char *input_N,
                         int radix_P, char *input_P,
                         int radix_Q, char *input_Q,
                         int radix_D, char *input_D,
                         int radix_E, char *input_E,
                         int is_priv,
                         int successive )
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    /* Exported MPI's */
    mbedtls_mpi Ne, Pe, Qe, De, Ee;

    const int have_N = ( strlen( input_N ) > 0 );
    const int have_P = ( strlen( input_P ) > 0 );
    const int have_Q = ( strlen( input_Q ) > 0 );
    const int have_D = ( strlen( input_D ) > 0 );
    const int have_E = ( strlen( input_E ) > 0 );

    mbedtls_rsa_context ctx;

    mbedtls_rsa_init( &ctx, 0, 0 );

    mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );

    mbedtls_mpi_init( &Ne );
    mbedtls_mpi_init( &Pe ); mbedtls_mpi_init( &Qe );
    mbedtls_mpi_init( &De ); mbedtls_mpi_init( &Ee );

    /* Setup RSA context */

    if( have_N )
        TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );

    if( have_P )
        TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );

    if( have_Q )
        TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );

    if( have_D )
        TEST_ASSERT( mbedtls_mpi_read_string( &D, radix_D, input_D ) == 0 );

    if( have_E )
        TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_import( &ctx,
                                     strlen( input_N ) ? &N : NULL,
                                     strlen( input_P ) ? &P : NULL,
                                     strlen( input_Q ) ? &Q : NULL,
                                     strlen( input_D ) ? &D : NULL,
                                     strlen( input_E ) ? &E : NULL ) == 0 );

    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );

    /*
     * Export parameters and compare to original ones.
     */

    /* N and E must always be present. */
    if( !successive )
    {
        TEST_ASSERT( mbedtls_rsa_export( &ctx, &Ne, NULL, NULL, NULL, &Ee ) == 0 );
    }
    else
    {
        TEST_ASSERT( mbedtls_rsa_export( &ctx, &Ne, NULL, NULL, NULL, NULL ) == 0 );
        TEST_ASSERT( mbedtls_rsa_export( &ctx, NULL, NULL, NULL, NULL, &Ee ) == 0 );
    }
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &N, &Ne ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &E, &Ee ) == 0 );

    /* If we were providing enough information to setup a complete private context,
     * we expect to be able to export all core parameters. */

    if( is_priv )
    {
        if( !successive )
        {
            TEST_ASSERT( mbedtls_rsa_export( &ctx, NULL, &Pe, &Qe,
                                             &De, NULL ) == 0 );
        }
        else
        {
            TEST_ASSERT( mbedtls_rsa_export( &ctx, NULL, &Pe, NULL,
                                             NULL, NULL ) == 0 );
            TEST_ASSERT( mbedtls_rsa_export( &ctx, NULL, NULL, &Qe,
                                             NULL, NULL ) == 0 );
            TEST_ASSERT( mbedtls_rsa_export( &ctx, NULL, NULL, NULL,
                                             &De, NULL ) == 0 );
        }

        if( have_P )
            TEST_ASSERT( mbedtls_mpi_cmp_mpi( &P, &Pe ) == 0 );

        if( have_Q )
            TEST_ASSERT( mbedtls_mpi_cmp_mpi( &Q, &Qe ) == 0 );

        if( have_D )
            TEST_ASSERT( mbedtls_mpi_cmp_mpi( &D, &De ) == 0 );

        /* While at it, perform a sanity check */
        TEST_ASSERT( mbedtls_rsa_validate_params( &Ne, &Pe, &Qe, &De, &Ee,
                                                       NULL, NULL ) == 0 );
    }

exit:

    mbedtls_rsa_free( &ctx );

    mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );

    mbedtls_mpi_free( &Ne );
    mbedtls_mpi_free( &Pe ); mbedtls_mpi_free( &Qe );
    mbedtls_mpi_free( &De ); mbedtls_mpi_free( &Ee );
}

#ifdef MBEDTLS_ENTROPY_C
#ifdef ENTROPY_HAVE_STRONG
#line 1130 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_validate_params( int radix_N, char *input_N,
                                  int radix_P, char *input_P,
                                  int radix_Q, char *input_Q,
                                  int radix_D, char *input_D,
                                  int radix_E, char *input_E,
                                  int prng, int result )
{
    /* Original MPI's with which we set up the RSA context */
    mbedtls_mpi N, P, Q, D, E;

    const int have_N = ( strlen( input_N ) > 0 );
    const int have_P = ( strlen( input_P ) > 0 );
    const int have_Q = ( strlen( input_Q ) > 0 );
    const int have_D = ( strlen( input_D ) > 0 );
    const int have_E = ( strlen( input_E ) > 0 );

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "test_suite_rsa";

    mbedtls_mpi_init( &N );
    mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E );

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    TEST_ASSERT( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) ) == 0 );

    if( have_N )
        TEST_ASSERT( mbedtls_mpi_read_string( &N, radix_N, input_N ) == 0 );

    if( have_P )
        TEST_ASSERT( mbedtls_mpi_read_string( &P, radix_P, input_P ) == 0 );

    if( have_Q )
        TEST_ASSERT( mbedtls_mpi_read_string( &Q, radix_Q, input_Q ) == 0 );

    if( have_D )
        TEST_ASSERT( mbedtls_mpi_read_string( &D, radix_D, input_D ) == 0 );

    if( have_E )
        TEST_ASSERT( mbedtls_mpi_read_string( &E, radix_E, input_E ) == 0 );

    TEST_ASSERT( mbedtls_rsa_validate_params( have_N ? &N : NULL,
                                        have_P ? &P : NULL,
                                        have_Q ? &Q : NULL,
                                        have_D ? &D : NULL,
                                        have_E ? &E : NULL,
                                        prng ? mbedtls_ctr_drbg_random : NULL,
                                        prng ? &ctr_drbg : NULL ) == result );
exit:

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_mpi_free( &N );
    mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E );
}
#endif /* MBEDTLS_ENTROPY_C */
#endif /* ENTROPY_HAVE_STRONG */

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
#line 1194 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_export_raw( char *input_N, char *input_P,
                             char *input_Q, char *input_D,
                             char *input_E, int is_priv,
                             int successive )
{
    /* Original raw buffers with which we set up the RSA context */
    unsigned char bufN[1000];
    unsigned char bufP[1000];
    unsigned char bufQ[1000];
    unsigned char bufD[1000];
    unsigned char bufE[1000];

    size_t lenN = 0;
    size_t lenP = 0;
    size_t lenQ = 0;
    size_t lenD = 0;
    size_t lenE = 0;

    /* Exported buffers */
    unsigned char bufNe[ sizeof( bufN ) ];
    unsigned char bufPe[ sizeof( bufP ) ];
    unsigned char bufQe[ sizeof( bufQ ) ];
    unsigned char bufDe[ sizeof( bufD ) ];
    unsigned char bufEe[ sizeof( bufE ) ];

    const int have_N = ( strlen( input_N ) > 0 );
    const int have_P = ( strlen( input_P ) > 0 );
    const int have_Q = ( strlen( input_Q ) > 0 );
    const int have_D = ( strlen( input_D ) > 0 );
    const int have_E = ( strlen( input_E ) > 0 );

    mbedtls_rsa_context ctx;

    mbedtls_rsa_init( &ctx, 0, 0 );

    /* Setup RSA context */

    if( have_N )
        lenN = unhexify( bufN, input_N );

    if( have_P )
        lenP = unhexify( bufP, input_P );

    if( have_Q )
        lenQ = unhexify( bufQ, input_Q );

    if( have_D )
        lenD = unhexify( bufD, input_D );

    if( have_E )
        lenE = unhexify( bufE, input_E );

    TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               have_N ? bufN : NULL, lenN,
                               have_P ? bufP : NULL, lenP,
                               have_Q ? bufQ : NULL, lenQ,
                               have_D ? bufD : NULL, lenD,
                               have_E ? bufE : NULL, lenE ) == 0 );

    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == 0 );

    /*
     * Export parameters and compare to original ones.
     */

    /* N and E must always be present. */
    if( !successive )
    {
        TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, bufNe, lenN,
                                             NULL, 0, NULL, 0, NULL, 0,
                                             bufEe, lenE ) == 0 );
    }
    else
    {
        TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, bufNe, lenN,
                                             NULL, 0, NULL, 0, NULL, 0,
                                             NULL, 0 ) == 0 );
        TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, NULL, 0,
                                             NULL, 0, NULL, 0, NULL, 0,
                                             bufEe, lenE ) == 0 );
    }
    TEST_ASSERT( memcmp( bufN, bufNe, lenN ) == 0 );
    TEST_ASSERT( memcmp( bufE, bufEe, lenE ) == 0 );

    /* If we were providing enough information to setup a complete private context,
     * we expect to be able to export all core parameters. */

    if( is_priv )
    {
        if( !successive )
        {
            TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, NULL, 0,
                                         bufPe, lenP ? lenP : sizeof( bufPe ),
                                         bufQe, lenQ ? lenQ : sizeof( bufQe ),
                                         bufDe, lenD ? lenD : sizeof( bufDe ),
                                         NULL, 0 ) == 0 );
        }
        else
        {
            TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, NULL, 0,
                                         bufPe, lenP ? lenP : sizeof( bufPe ),
                                         NULL, 0, NULL, 0,
                                         NULL, 0 ) == 0 );

            TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, NULL, 0, NULL, 0,
                                         bufQe, lenQ ? lenQ : sizeof( bufQe ),
                                         NULL, 0, NULL, 0 ) == 0 );

            TEST_ASSERT( mbedtls_rsa_export_raw( &ctx, NULL, 0, NULL, 0,
                                         NULL, 0, bufDe, lenD ? lenD : sizeof( bufDe ),
                                         NULL, 0 ) == 0 );
        }

        if( have_P )
            TEST_ASSERT( memcmp( bufP, bufPe, lenP ) == 0 );

        if( have_Q )
            TEST_ASSERT( memcmp( bufQ, bufQe, lenQ ) == 0 );

        if( have_D )
            TEST_ASSERT( memcmp( bufD, bufDe, lenD ) == 0 );

    }

exit:
    mbedtls_rsa_free( &ctx );
}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */

#ifdef MBEDTLS_CTR_DRBG_C
#ifdef MBEDTLS_ENTROPY_C
#ifdef ENTROPY_HAVE_STRONG
#line 1324 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_mbedtls_rsa_import_raw( char *input_N,
                             char *input_P, char *input_Q,
                             char *input_D, char *input_E,
                             int successive,
                             int is_priv,
                             int res_check,
                             int res_complete )
{
    unsigned char bufN[1000];
    unsigned char bufP[1000];
    unsigned char bufQ[1000];
    unsigned char bufD[1000];
    unsigned char bufE[1000];

    /* Buffers used for encryption-decryption test */
    unsigned char *buf_orig = NULL;
    unsigned char *buf_enc  = NULL;
    unsigned char *buf_dec  = NULL;

    size_t lenN = 0;
    size_t lenP = 0;
    size_t lenQ = 0;
    size_t lenD = 0;
    size_t lenE = 0;

    mbedtls_rsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char *pers = "test_suite_rsa";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_rsa_init( &ctx, 0, 0 );

    TEST_ASSERT( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) ) == 0 );

    if( strlen( input_N ) )
        lenN = unhexify( bufN, input_N );

    if( strlen( input_P ) )
        lenP = unhexify( bufP, input_P );

    if( strlen( input_Q ) )
        lenQ = unhexify( bufQ, input_Q );

    if( strlen( input_D ) )
        lenD = unhexify( bufD, input_D );

    if( strlen( input_E ) )
        lenE = unhexify( bufE, input_E );

    if( !successive )
    {
        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               ( lenN > 0 ) ? bufN : NULL, lenN,
                               ( lenP > 0 ) ? bufP : NULL, lenP,
                               ( lenQ > 0 ) ? bufQ : NULL, lenQ,
                               ( lenD > 0 ) ? bufD : NULL, lenD,
                               ( lenE > 0 ) ? bufE : NULL, lenE ) == 0 );
    }
    else
    {
        /* Import N, P, Q, D, E separately.
         * This should make no functional difference. */

        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               ( lenN > 0 ) ? bufN : NULL, lenN,
                               NULL, 0, NULL, 0, NULL, 0, NULL, 0 ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               NULL, 0,
                               ( lenP > 0 ) ? bufP : NULL, lenP,
                               NULL, 0, NULL, 0, NULL, 0 ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               NULL, 0, NULL, 0,
                               ( lenQ > 0 ) ? bufQ : NULL, lenQ,
                               NULL, 0, NULL, 0 ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               NULL, 0, NULL, 0, NULL, 0,
                               ( lenD > 0 ) ? bufD : NULL, lenD,
                               NULL, 0 ) == 0 );

        TEST_ASSERT( mbedtls_rsa_import_raw( &ctx,
                               NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                               ( lenE > 0 ) ? bufE : NULL, lenE ) == 0 );
    }

    TEST_ASSERT( mbedtls_rsa_complete( &ctx ) == res_complete );

    /* On expected success, perform some public and private
     * key operations to check if the key is working properly. */
    if( res_complete == 0 )
    {
        if( is_priv )
            TEST_ASSERT( mbedtls_rsa_check_privkey( &ctx ) == res_check );
        else
            TEST_ASSERT( mbedtls_rsa_check_pubkey( &ctx ) == res_check );

        if( res_check != 0 )
            goto exit;

        buf_orig = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        buf_enc  = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        buf_dec  = mbedtls_calloc( 1, mbedtls_rsa_get_len( &ctx ) );
        if( buf_orig == NULL || buf_enc == NULL || buf_dec == NULL )
            goto exit;

        TEST_ASSERT( mbedtls_ctr_drbg_random( &ctr_drbg,
                              buf_orig, mbedtls_rsa_get_len( &ctx ) ) == 0 );

        /* Make sure the number we're generating is smaller than the modulus */
        buf_orig[0] = 0x00;

        TEST_ASSERT( mbedtls_rsa_public( &ctx, buf_orig, buf_enc ) == 0 );

        if( is_priv )
        {
            TEST_ASSERT( mbedtls_rsa_private( &ctx, mbedtls_ctr_drbg_random,
                                              &ctr_drbg, buf_enc,
                                              buf_dec ) == 0 );

            TEST_ASSERT( memcmp( buf_orig, buf_dec,
                                 mbedtls_rsa_get_len( &ctx ) ) == 0 );
        }
    }

exit:

    mbedtls_free( buf_orig );
    mbedtls_free( buf_enc  );
    mbedtls_free( buf_dec  );

    mbedtls_rsa_free( &ctx );

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

}
#endif /* MBEDTLS_CTR_DRBG_C */
#endif /* MBEDTLS_ENTROPY_C */
#endif /* ENTROPY_HAVE_STRONG */

#ifdef MBEDTLS_SELF_TEST
#line 1470 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.function"
void test_suite_rsa_selftest()
{
    TEST_ASSERT( mbedtls_rsa_self_test( 1 ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_SELF_TEST */


#endif /* defined(MBEDTLS_RSA_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */
#endif /* defined(MBEDTLS_GENPRIME) */


#line 77 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "!MBEDTLS_RSA_NO_CRT" ) == 0 )
    {
#if !defined(MBEDTLS_RSA_NO_CRT)
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
    if( strcmp( str, "MBEDTLS_SELF_TEST" ) == 0 )
    {
#if defined(MBEDTLS_SELF_TEST)
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
    if( strcmp( str, "MBEDTLS_SHA512_C" ) == 0 )
    {
#if defined(MBEDTLS_SHA512_C)
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

    if( strcmp( params[0], "mbedtls_rsa_pkcs1_sign" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        char *param12 = params[12];
        char *param13 = params[13];
        int param14;

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[14], &param14 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_pkcs1_sign( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_verify" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_pkcs1_verify( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_sign_raw" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        char *param12 = params[12];
        char *param13 = params[13];

        if( cnt != 14 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 14 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_rsa_pkcs1_sign_raw( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_verify_raw" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        char *param9 = params[9];
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_rsa_pkcs1_verify_raw( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_encrypt" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_pkcs1_encrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_pkcs1_encrypt_bad_rng" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        char *param8 = params[8];
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_rsa_pkcs1_encrypt_bad_rng( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_pkcs1_decrypt" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[14], &param14 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_pkcs1_decrypt( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_public" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        char *param7 = params[7];
        int param8;

        if( cnt != 9 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 9 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_public( param1, param2, param3, param4, param5, param6, param7, param8 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_private" ) == 0 )
    {

        char *param1 = params[1];
        int param2;
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        char *param11 = params[11];
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_private( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_check_privkey_null" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_rsa_check_privkey_null(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_check_pubkey" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;

        if( cnt != 6 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 6 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_check_pubkey( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_check_privkey" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;
        char *param15 = params[15];
        int param16;
        char *param17 = params[17];
        int param18;

        if( cnt != 19 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 19 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[14], &param14 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param15 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[16], &param16 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param17 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[18], &param18 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_check_privkey( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14, param15, param16, param17, param18 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_check_pubpriv" ) == 0 )
    {

        int param1;
        int param2;
        char *param3 = params[3];
        int param4;
        char *param5 = params[5];
        int param6;
        char *param7 = params[7];
        int param8;
        char *param9 = params[9];
        int param10;
        char *param11 = params[11];
        int param12;
        char *param13 = params[13];
        int param14;
        char *param15 = params[15];
        int param16;
        char *param17 = params[17];
        int param18;
        char *param19 = params[19];
        int param20;
        char *param21 = params[21];
        int param22;

        if( cnt != 23 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 23 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[14], &param14 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param15 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[16], &param16 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param17 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[18], &param18 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param19 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[20], &param20 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param21 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[22], &param22 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_rsa_check_pubpriv( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14, param15, param16, param17, param18, param19, param20, param21, param22 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_gen_key" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C
    #ifdef ENTROPY_HAVE_STRONG

        int param1;
        int param2;
        int param3;

        if( cnt != 4 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_gen_key( param1, param2, param3 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */
    #endif /* ENTROPY_HAVE_STRONG */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_deduce_primes" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_deduce_primes( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_deduce_private_exponent" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        int param10;

        if( cnt != 11 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 11 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[10], &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_deduce_private_exponent( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_import" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C
    #ifdef ENTROPY_HAVE_STRONG

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        int param12;
        int param13;
        int param14;

        if( cnt != 15 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 15 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[13], &param13 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[14], &param14 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_import( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12, param13, param14 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */
    #endif /* ENTROPY_HAVE_STRONG */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_export" ) == 0 )
    {

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_export( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_validate_params" ) == 0 )
    {
    #ifdef MBEDTLS_ENTROPY_C
    #ifdef ENTROPY_HAVE_STRONG

        int param1;
        char *param2 = params[2];
        int param3;
        char *param4 = params[4];
        int param5;
        char *param6 = params[6];
        int param7;
        char *param8 = params[8];
        int param9;
        char *param10 = params[10];
        int param11;
        int param12;

        if( cnt != 13 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 13 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[3], &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[5], &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param10 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[11], &param11 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[12], &param12 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_validate_params( param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, param12 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_ENTROPY_C */
    #endif /* ENTROPY_HAVE_STRONG */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_export_raw" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        int param6;
        int param7;

        if( cnt != 8 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 8 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_export_raw( param1, param2, param3, param4, param5, param6, param7 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "mbedtls_rsa_import_raw" ) == 0 )
    {
    #ifdef MBEDTLS_CTR_DRBG_C
    #ifdef MBEDTLS_ENTROPY_C
    #ifdef ENTROPY_HAVE_STRONG

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        char *param4 = params[4];
        char *param5 = params[5];
        int param6;
        int param7;
        int param8;
        int param9;

        if( cnt != 10 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 10 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param5 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[6], &param6 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[7], &param7 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[8], &param8 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[9], &param9 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_mbedtls_rsa_import_raw( param1, param2, param3, param4, param5, param6, param7, param8, param9 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_CTR_DRBG_C */
    #endif /* MBEDTLS_ENTROPY_C */
    #endif /* ENTROPY_HAVE_STRONG */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "rsa_selftest" ) == 0 )
    {
    #ifdef MBEDTLS_SELF_TEST


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_rsa_selftest(  );
        return ( DISPATCH_TEST_SUCCESS );
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
    "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.data"


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
    const char *default_filename = "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_rsa.data";
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

