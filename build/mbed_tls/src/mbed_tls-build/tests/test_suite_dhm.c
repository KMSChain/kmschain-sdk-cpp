/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_dhm.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/main_test.function
 *      Helper file     : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/helpers.function
 *      Test suite file : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.function
 *      Test suite data : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.data
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

#if defined(MBEDTLS_DHM_C)
#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/dhm.h"

#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_DHM_C)
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

    if( strcmp( str, "MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED );
        return( KEY_VALUE_MAPPING_FOUND );
    }
    if( strcmp( str, "MBEDTLS_ERR_DHM_BAD_INPUT_DATA" ) == 0 )
    {
        *value = ( MBEDTLS_ERR_DHM_BAD_INPUT_DATA );
        return( KEY_VALUE_MAPPING_FOUND );
    }


    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 11 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.function"
void test_suite_dhm_do_dhm( int radix_P, char *input_P,
                 int radix_G, char *input_G, int result )
{
    mbedtls_dhm_context ctx_srv;
    mbedtls_dhm_context ctx_cli;
    unsigned char ske[1000];
    unsigned char *p = ske;
    unsigned char pub_cli[1000];
    unsigned char sec_srv[1000];
    unsigned char sec_cli[1000];
    size_t ske_len = 0;
    size_t pub_cli_len = 0;
    size_t sec_srv_len;
    size_t sec_cli_len;
    int x_size, i;
    rnd_pseudo_info rnd_info;

    mbedtls_dhm_init( &ctx_srv );
    mbedtls_dhm_init( &ctx_cli );
    memset( ske, 0x00, 1000 );
    memset( pub_cli, 0x00, 1000 );
    memset( sec_srv, 0x00, 1000 );
    memset( sec_cli, 0x00, 1000 );
    memset( &rnd_info, 0x00, sizeof( rnd_pseudo_info ) );

    /*
     * Set params
     */
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.P, radix_P, input_P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &ctx_srv.G, radix_G, input_G ) == 0 );
    x_size = mbedtls_mpi_size( &ctx_srv.P );
    pub_cli_len = x_size;

    /*
     * First key exchange
     */
    TEST_ASSERT( mbedtls_dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &rnd_pseudo_rand, &rnd_info ) == result );
    if ( result != 0 )
        goto exit;

    ske[ske_len++] = 0;
    ske[ske_len++] = 0;
    TEST_ASSERT( mbedtls_dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_srv, sec_srv, sizeof( sec_srv ), &sec_srv_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_cli, sec_cli, sizeof( sec_cli ), &sec_cli_len, NULL, NULL ) == 0 );

    TEST_ASSERT( sec_srv_len == sec_cli_len );
    TEST_ASSERT( sec_srv_len != 0 );
    TEST_ASSERT( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );

    /* Re-do calc_secret on server a few times to test update of blinding values */
    for( i = 0; i < 3; i++ )
    {
        sec_srv_len = 1000;
        TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_srv, sec_srv, sizeof( sec_srv ), &sec_srv_len, &rnd_pseudo_rand, &rnd_info ) == 0 );

        TEST_ASSERT( sec_srv_len == sec_cli_len );
        TEST_ASSERT( sec_srv_len != 0 );
        TEST_ASSERT( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );
    }

    /*
     * Second key exchange to test change of blinding values on server
     */
    p = ske;

    TEST_ASSERT( mbedtls_dhm_make_params( &ctx_srv, x_size, ske, &ske_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    ske[ske_len++] = 0;
    ske[ske_len++] = 0;
    TEST_ASSERT( mbedtls_dhm_read_params( &ctx_cli, &p, ske + ske_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_make_public( &ctx_cli, x_size, pub_cli, pub_cli_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_read_public( &ctx_srv, pub_cli, pub_cli_len ) == 0 );

    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_srv, sec_srv, sizeof( sec_srv ), &sec_srv_len, &rnd_pseudo_rand, &rnd_info ) == 0 );
    TEST_ASSERT( mbedtls_dhm_calc_secret( &ctx_cli, sec_cli, sizeof( sec_cli ), &sec_cli_len, NULL, NULL ) == 0 );

    TEST_ASSERT( sec_srv_len == sec_cli_len );
    TEST_ASSERT( sec_srv_len != 0 );
    TEST_ASSERT( memcmp( sec_srv, sec_cli, sec_srv_len ) == 0 );

exit:
    mbedtls_dhm_free( &ctx_srv );
    mbedtls_dhm_free( &ctx_cli );
}

#ifdef MBEDTLS_FS_IO
#line 103 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.function"
void test_suite_dhm_file( char *filename, char *p, char *g, int len )
{
    mbedtls_dhm_context ctx;
    mbedtls_mpi P, G;

    mbedtls_dhm_init( &ctx );
    mbedtls_mpi_init( &P ); mbedtls_mpi_init( &G );

    TEST_ASSERT( mbedtls_mpi_read_string( &P, 16, p ) == 0 );
    TEST_ASSERT( mbedtls_mpi_read_string( &G, 16, g ) == 0 );

    TEST_ASSERT( mbedtls_dhm_parse_dhmfile( &ctx, filename ) == 0 );

    TEST_ASSERT( ctx.len == (size_t) len );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &ctx.P, &P ) == 0 );
    TEST_ASSERT( mbedtls_mpi_cmp_mpi( &ctx.G, &G ) == 0 );

exit:
    mbedtls_mpi_free( &P ); mbedtls_mpi_free( &G );
    mbedtls_dhm_free( &ctx );
}
#endif /* MBEDTLS_FS_IO */

#ifdef MBEDTLS_SELF_TEST
#line 127 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.function"
void test_suite_dhm_selftest()
{
    TEST_ASSERT( mbedtls_dhm_self_test( 1 ) == 0 );

exit:
    return;
}
#endif /* MBEDTLS_SELF_TEST */


#endif /* defined(MBEDTLS_DHM_C) */
#endif /* defined(MBEDTLS_BIGNUM_C) */


#line 77 "main_test.function"


/*----------------------------------------------------------------------------*/
/* Test dispatch code */

int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );


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

    if( strcmp( params[0], "dhm_do_dhm" ) == 0 )
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

        test_suite_dhm_do_dhm( param1, param2, param3, param4, param5 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "dhm_file" ) == 0 )
    {
    #ifdef MBEDTLS_FS_IO

        char *param1 = params[1];
        char *param2 = params[2];
        char *param3 = params[3];
        int param4;

        if( cnt != 5 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_string( &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_string( &param3 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[4], &param4 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_dhm_file( param1, param2, param3, param4 );
        return ( DISPATCH_TEST_SUCCESS );
    #endif /* MBEDTLS_FS_IO */

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "dhm_selftest" ) == 0 )
    {
    #ifdef MBEDTLS_SELF_TEST


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_dhm_selftest(  );
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
    "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.data"


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
    const char *default_filename = "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_dhm.data";
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

