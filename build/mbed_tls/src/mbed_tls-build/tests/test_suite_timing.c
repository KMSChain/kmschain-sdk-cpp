/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script: /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/scripts/generate_code.pl
 *
 * Test file      : test_suite_timing.c
 *
 * The following files were used to create this file.
 *
 *      Main code file  : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/main_test.function
 *      Helper file     : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/helpers.function
 *      Test suite file : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function
 *      Test suite data : /home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.data
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

#if defined(MBEDTLS_TIMING_C)


/* This test module exercises the timing module. One of the expected failure
   modes is for timers to never expire, which could lead to an infinite loop.
   The function timing_timer_simple is protected against this failure mode and
   checks that timers do expire. Other functions will terminate if their
   timers do expire. Therefore it is recommended to run timing_timer_simple
   first and run other test functions only if that timing_timer_simple
   succeeded. */

#include <limits.h>

#include "mbedtls/timing.h"

/* Wait this many milliseconds for a short timing test. This duration
   should be large enough that, in practice, if you read the timer
   value twice in a row, it won't have jumped by that much. */
#define TIMING_SHORT_TEST_MS 100

/* A loop that waits TIMING_SHORT_TEST_MS must not take more than this many
   iterations. This value needs to be large enough to accommodate fast
   platforms (e.g. at 4GHz and 10 cycles/iteration a CPU can run through 20
   million iterations in 50ms). The only motivation to keep this value low is
   to avoid having an infinite loop if the timer functions are not implemented
   correctly. Ideally this value should be based on the processor speed but we
   don't have this information! */
#define TIMING_SHORT_TEST_ITERATIONS_MAX 1e8

/* alarm(0) must fire in no longer than this amount of time. */
#define TIMING_ALARM_0_DELAY_MS TIMING_SHORT_TEST_MS

static int expected_delay_status( uint32_t int_ms, uint32_t fin_ms,
                                  unsigned long actual_ms )
{
    return( fin_ms == 0 ? -1 :
            actual_ms >= fin_ms ? 2 :
            actual_ms >= int_ms ? 1 :
            0 );
}

/* Some conditions in timing_timer_simple suggest that timers are unreliable.
   Most other test cases rely on timers to terminate, and could loop
   indefinitely if timers are too broken. So if timing_timer_simple detected a
   timer that risks not terminating (going backwards, or not reaching the
   desired count in the alloted clock cycles), set this flag to immediately
   fail those other tests without running any timers. */
static int timers_are_badly_broken = 0;


#endif /* defined(MBEDTLS_TIMING_C) */


#line 1 "main_test.function"
#if defined(MBEDTLS_TIMING_C)

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



    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/*----------------------------------------------------------------------------*/
/* Test Case code */

#line 57 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_timer_simple( )
{
    struct mbedtls_timing_hr_time timer;
    unsigned long millis = 0;
    unsigned long new_millis = 0;
    unsigned long iterations = 0;
    /* Start the timer. */
    (void) mbedtls_timing_get_timer( &timer, 1 );
    /* Busy-wait loop for a few milliseconds. */
    do
    {
        new_millis = mbedtls_timing_get_timer( &timer, 0 );
        ++iterations;
        /* Check that the timer didn't go backwards */
        TEST_ASSERT( new_millis >= millis );
        millis = new_millis;
    }
    while( millis < TIMING_SHORT_TEST_MS &&
           iterations <= TIMING_SHORT_TEST_ITERATIONS_MAX );
    /* The wait duration should have been large enough for at least a
       few runs through the loop, even on the slowest realistic platform. */
    TEST_ASSERT( iterations >= 2 );
    /* The wait duration shouldn't have overflowed the iteration count. */
    TEST_ASSERT( iterations < TIMING_SHORT_TEST_ITERATIONS_MAX );
    return;

exit:
    if( iterations >= TIMING_SHORT_TEST_ITERATIONS_MAX ||
        new_millis < millis )
    {
        /* The timer was very unreliable: it didn't increment and the loop ran
           out, or it went backwards. Other tests that use timers might go
           into an infinite loop, so we'll skip them. */
        timers_are_badly_broken = 1;
    }

    /* No cleanup needed, but show some diagnostic iterations, because timing
       problems can be hard to reproduce. */
    mbedtls_fprintf( stdout, "  Finished with millis=%lu new_millis=%lu get(timer)<=%lu iterations=%lu\n",
                     millis, new_millis, mbedtls_timing_get_timer( &timer, 0 ),
                     iterations );
}

#line 102 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_timer_reset( )
{
    struct mbedtls_timing_hr_time timer;
    unsigned long millis = 0;
    unsigned long iterations = 0;

    /* Skip this test if it looks like timers don't work at all, to avoid an
       infinite loop below. */
    TEST_ASSERT( !timers_are_badly_broken );

    /* Start the timer. Timers are always reset to 0. */
    TEST_ASSERT( mbedtls_timing_get_timer( &timer, 1 ) == 0 );
    /* Busy-wait loop for a few milliseconds */
    do
    {
        ++iterations;
        millis = mbedtls_timing_get_timer( &timer, 0 );
    }
    while( millis < TIMING_SHORT_TEST_MS );

    /* Reset the timer and check that it has restarted. */
    TEST_ASSERT( mbedtls_timing_get_timer( &timer, 1 ) == 0 );
    /* Read the timer immediately after reset. It should be 0 or close
       to it. */
    TEST_ASSERT( mbedtls_timing_get_timer( &timer, 0 ) < TIMING_SHORT_TEST_MS );
    return;

exit:
    /* No cleanup needed, but show some diagnostic information, because timing
       problems can be hard to reproduce. */
    if( !timers_are_badly_broken )
        mbedtls_fprintf( stdout, "  Finished with millis=%lu get(timer)<=%lu iterations=%lu\n",
                         millis, mbedtls_timing_get_timer( &timer, 0 ),
                         iterations );
}

#line 140 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_two_timers( int delta )
{
    struct mbedtls_timing_hr_time timer1, timer2;
    unsigned long millis1 = 0, millis2 = 0;

    /* Skip this test if it looks like timers don't work at all, to avoid an
       infinite loop below. */
    TEST_ASSERT( !timers_are_badly_broken );

    /* Start the first timer and wait for a short time. */
    (void) mbedtls_timing_get_timer( &timer1, 1 );
    do
    {
        millis1 = mbedtls_timing_get_timer( &timer1, 0 );
    }
    while( millis1 < TIMING_SHORT_TEST_MS );

    /* Do a short busy-wait, so that the difference between timer1 and timer2
       doesn't practically always end up being very close to a whole number of
       milliseconds. */
    while( delta > 0 )
        --delta;

    /* Start the second timer and compare it with the first. */
    mbedtls_timing_get_timer( &timer2, 1 );
    do
    {
        millis1 = mbedtls_timing_get_timer( &timer1, 0 );
        millis2 = mbedtls_timing_get_timer( &timer2, 0 );
        /* The first timer should always be ahead of the first. */
        TEST_ASSERT( millis1 > millis2 );
        /* The timers shouldn't drift apart, i.e. millis2-millis1 should stay
           roughly constant, but this is hard to test reliably, especially in
           a busy environment such as an overloaded continuous integration
           system, so we don't test it it. */
    }
    while( millis2 < TIMING_SHORT_TEST_MS );

    return;

exit:
    /* No cleanup needed, but show some diagnostic iterations, because timing
       problems can be hard to reproduce. */
    if( !timers_are_badly_broken )
        mbedtls_fprintf( stdout, "  Finished with millis1=%lu get(timer1)<=%lu millis2=%lu get(timer2)<=%lu\n",
                         millis1, mbedtls_timing_get_timer( &timer1, 0 ),
                         millis2, mbedtls_timing_get_timer( &timer2, 0 ) );
}

#line 191 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_alarm( int seconds )
{
    struct mbedtls_timing_hr_time timer;
    unsigned long millis = 0;
    /* We check that about the desired number of seconds has elapsed. Be
       slightly liberal with the lower bound, so as to allow platforms where
       the alarm (with second resolution) and the timer (with millisecond
       resolution) are based on different clocks. Be very liberal with the
       upper bound, because the platform might be busy. */
    unsigned long millis_min = ( seconds > 0 ?
                                 seconds * 900 :
                                 0 );
    unsigned long millis_max = ( seconds > 0 ?
                                 seconds * 1100 + 400 :
                                 TIMING_ALARM_0_DELAY_MS );
    unsigned long iterations = 0;

    /* Skip this test if it looks like timers don't work at all, to avoid an
       infinite loop below. */
    TEST_ASSERT( !timers_are_badly_broken );

    /* Set an alarm and count how long it takes with a timer. */
    (void) mbedtls_timing_get_timer( &timer, 1 );
    mbedtls_set_alarm( seconds );

    if( seconds > 0 )
    {
        /* We set the alarm for at least 1 second. It should not have fired
           immediately, even on a slow and busy platform. */
        TEST_ASSERT( !mbedtls_timing_alarmed );
    }
    /* A 0-second alarm should fire quickly, but we don't guarantee that it
       fires immediately, so mbedtls_timing_alarmed may or may not be set at
       this point. */

    /* Busy-wait until the alarm rings */
    do
    {
        ++iterations;
        millis = mbedtls_timing_get_timer( &timer, 0 );
    }
    while( !mbedtls_timing_alarmed && millis <= millis_max );

    TEST_ASSERT( mbedtls_timing_alarmed );
    TEST_ASSERT( millis >= millis_min );
    TEST_ASSERT( millis <= millis_max );

    mbedtls_timing_alarmed = 0;
    return;

exit:
    /* Show some diagnostic iterations, because timing
       problems can be hard to reproduce. */
    if( !timers_are_badly_broken )
        mbedtls_fprintf( stdout, "  Finished with alarmed=%d millis=%lu get(timer)<=%lu iterations=%lu\n",
                         mbedtls_timing_alarmed,
                         millis, mbedtls_timing_get_timer( &timer, 0 ),
                         iterations );
    /* Cleanup */
    mbedtls_timing_alarmed = 0;
}

#line 255 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_delay( int int_ms, int fin_ms )
{
    /* This function assumes that if int_ms is nonzero then it is large
       enough that we have time to read all timers at least once in an
       interval of time lasting int_ms milliseconds, and likewise for (fin_ms
       - int_ms). So don't call it with arguments that are too small. */

    mbedtls_timing_delay_context delay;
    struct mbedtls_timing_hr_time timer;
    unsigned long delta = 0; /* delay started between timer=0 and timer=delta */
    unsigned long before = 0, after = 0;
    unsigned long iterations = 0;
    int status = -2;
    int saw_status_1 = 0;
    int warn_inconclusive = 0;

    assert( int_ms >= 0 );
    assert( fin_ms >= 0 );

    /* Skip this test if it looks like timers don't work at all, to avoid an
       infinite loop below. */
    TEST_ASSERT( !timers_are_badly_broken );

    /* Start a reference timer. Program a delay, and verify that the status of
       the delay is consistent with the time given by the reference timer. */
    (void) mbedtls_timing_get_timer( &timer, 1 );
    mbedtls_timing_set_delay( &delay, int_ms, fin_ms );
    /* Set delta to an upper bound for the interval between the start of timer
       and the start of delay. Reading timer after starting delay gives us an
       upper bound for the interval, rounded to a 1ms precision. Since this
       might have been rounded down, but we need an upper bound, we add 1. */
    delta = mbedtls_timing_get_timer( &timer, 0 ) + 1;

    status = mbedtls_timing_get_delay( &delay );
    if( fin_ms == 0 )
    {
        /* Cancelled timer. Just check the correct status for this case. */
        TEST_ASSERT( status == -1 );
        return;
    }

    /* Initially, none of the delays must be passed yet if they're nonzero.
       This could fail for very small values of int_ms and fin_ms, where "very
       small" depends how fast and how busy the platform is. */
    if( int_ms > 0 )
    {
        TEST_ASSERT( status == 0 );
    }
    else
    {
        TEST_ASSERT( status == 1 );
    }

    do
    {
        unsigned long delay_min, delay_max;
        int status_min, status_max;
        ++iterations;
        before = mbedtls_timing_get_timer( &timer, 0 );
        status = mbedtls_timing_get_delay( &delay );
        after = mbedtls_timing_get_timer( &timer, 0 );
        /* At a time between before and after, the delay's status was status.
           Check that this is consistent given that the delay was started
           between times 0 and delta. */
        delay_min = ( before > delta ? before - delta : 0 );
        status_min = expected_delay_status( int_ms, fin_ms, delay_min );
        delay_max = after;
        status_max = expected_delay_status( int_ms, fin_ms, delay_max );
        TEST_ASSERT( status >= status_min );
        TEST_ASSERT( status <= status_max );
        if( status == 1 )
            saw_status_1 = 1;
    }
    while ( before <= fin_ms + delta && status != 2 );

    /* Since we've waited at least fin_ms, the delay must have fully
       expired. */
    TEST_ASSERT( status == 2 );

    /* If the second delay is more than the first, then there must have been a
       point in time when the first delay was passed but not the second delay.
       This could fail for very small values of (fin_ms - int_ms), where "very
       small" depends how fast and how busy the platform is. In practice, this
       is the test that's most likely to fail on a heavily loaded machine. */
    if( fin_ms > int_ms )
    {
        warn_inconclusive = 1;
        TEST_ASSERT( saw_status_1 );
    }

    return;

exit:
    /* No cleanup needed, but show some diagnostic iterations, because timing
       problems can be hard to reproduce. */
    if( !timers_are_badly_broken )
        mbedtls_fprintf( stdout, "  Finished with delta=%lu before=%lu after=%lu status=%d iterations=%lu\n",
                         delta, before, after, status, iterations );
    if( warn_inconclusive )
        mbedtls_fprintf( stdout, "  Inconclusive test, try running it on a less heavily loaded machine.\n" );
 }

#line 359 "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.function"
void test_suite_timing_hardclock( )
{
    /* We make very few guarantees about mbedtls_timing_hardclock: its rate is
       platform-dependent, it can wrap around. So there isn't much we can
       test. But we do at least test that it doesn't crash, stall or return
       completely nonsensical values. */

    struct mbedtls_timing_hr_time timer;
    unsigned long hardclock0 = -1, hardclock1 = -1, delta1 = -1;

    /* Skip this test if it looks like timers don't work at all, to avoid an
       infinite loop below. */
    TEST_ASSERT( !timers_are_badly_broken );

    hardclock0 = mbedtls_timing_hardclock( );
    /* Wait 2ms to ensure a nonzero delay. Since the timer interface has 1ms
       resolution and unspecified precision, waiting 1ms might be a very small
       delay that's rounded up. */
    (void) mbedtls_timing_get_timer( &timer, 1 );
    while( mbedtls_timing_get_timer( &timer, 0 ) < 2 )
        /*busy-wait loop*/;
    hardclock1 = mbedtls_timing_hardclock( );

    /* Although the hardclock counter can wrap around, the difference
       (hardclock1 - hardclock0) is taken modulo the type size, so it is
       correct as long as the counter only wrapped around at most once. We
       further require the difference to be nonzero (after a wait of more than
       1ms, the counter must have changed), and not to be overly large (after
       a wait of less than 3ms, plus time lost because other processes were
       scheduled on the CPU). If the hardclock counter runs at 4GHz, then
       1000000000 (which is 1/4 of the counter wraparound on a 32-bit machine)
       allows 250ms. */
    delta1 = hardclock1 - hardclock0;
    TEST_ASSERT( delta1 > 0 );
    TEST_ASSERT( delta1 < 1000000000 );
    return;

exit:
    /* No cleanup needed, but show some diagnostic iterations, because timing
       problems can be hard to reproduce. */
    if( !timers_are_badly_broken )
        mbedtls_fprintf( stdout, "  Finished with hardclock=%lu,%lu\n",
                         hardclock0, hardclock1 );
}


#endif /* defined(MBEDTLS_TIMING_C) */


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

    if( strcmp( params[0], "timing_timer_simple" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_timing_timer_simple(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "timing_timer_reset" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_timing_timer_reset(  );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "timing_two_timers" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_timing_two_timers( param1 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "timing_alarm" ) == 0 )
    {

        int param1;

        if( cnt != 2 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 2 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_timing_alarm( param1 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "timing_delay" ) == 0 )
    {

        int param1;
        int param2;

        if( cnt != 3 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 3 );
            return( DISPATCH_INVALID_TEST_DATA );
        }

        if( verify_int( params[1], &param1 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );
        if( verify_int( params[2], &param2 ) != 0 ) return( DISPATCH_INVALID_TEST_DATA );

        test_suite_timing_delay( param1, param2 );
        return ( DISPATCH_TEST_SUCCESS );

        return ( DISPATCH_UNSUPPORTED_SUITE );
    }
    else
    if( strcmp( params[0], "timing_hardclock" ) == 0 )
    {


        if( cnt != 1 )
        {
            mbedtls_fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( DISPATCH_INVALID_TEST_DATA );
        }


        test_suite_timing_hardclock(  );
        return ( DISPATCH_TEST_SUCCESS );

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
    "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.data"


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
    const char *default_filename = "/home/gegham/Desktop/kmschain/kmschain-sdk-cpp/build/mbed_tls/src/mbed_tls/tests/suites/test_suite_timing.data";
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

