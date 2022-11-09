/**********************************************
*
*  _________ _________ ___________ _________
* |         |         |   |   |   |         |
* |_________|         |   |   |   |    _    |
* |         |    |    |   |   |   |         |
* |         |    |    |           |         |
* |         |    |    |           |    |    |
* |         |         |           |    |    |
* |_________|_________|___________|____|____|
*
* Copyright (c) 2016 IoTerop.
* All rights reserved.
*
**********************************************/

// Platform specific headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"

#include "psa/crypto.h"


static void prv_logBuffer(const uint8_t *buffer,
                          size_t bufferLength)
{
    size_t i;

    printf("%lu bytes\r\n", bufferLength);

    for (i = 0; i < bufferLength; i += 16)
    {
        size_t j;

        printf("  ");

        // Print the buffer by byte
        for (j = 0; j < 16 && i + j < bufferLength; j++)
        {
            printf("%02X ", buffer[i + j]);
            if (j % 4 == 3)
            {
                printf(" ");
            }
        }

        // Complete the line with whitespace if there are not 16 bytes
        while (j < 16) // keep the previous value for the variable 'j'
        {
            printf("   ");
            if (j % 4 == 3)
            {
                printf(" ");
            }
            j++;
        }

        printf(" |");

        // Print the buffer with writable character if possible
        for (j = 0; j < 16 && i + j < bufferLength; j++)
        {
            if (isprint(buffer[i + j])
                && !isspace(buffer[i + j]))
            {
                printf("%c", buffer[i + j]);
            }
            else
            {
                printf(".");
            }
        }
        printf("|\r\n");
    }
    printf("\r\n");
}

// From https://github.com/mwarning/mbedtls_ecp_compression
// Under Creative Commons Zero v1.0 Universal

int mbedtls_ecp_decompress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    int ret;
    size_t plen;
    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    plen = mbedtls_mpi_size(&grp->P);

    *olen = 2 * plen + 1;

    if (osize < *olen)
        return(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (ilen != plen + 1)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (input[0] != 0x02 && input[0] != 0x03)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // output will consist of 0x04|X|Y
    memcpy(output, input, ilen);
    output[0] = 0x04;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n);

    // x <= input
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input + 1, plen));

    // r = x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

    // r = x^2 + a
    if (grp->A.p == NULL) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

    // Calculate square root of r over finite field P:
    //   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

    // r ^ ((P + 1) / 4) (mod p)
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

    // Select solution that has the correct "sign" (equals odd/even solution in finite group)
    if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
        // r = p - r
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
    }

    // y => output
    ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&n);

    return(ret);
}

// from https://github.com/Mbed-TLS/mbedtls/pull/6282

static int mbedtls_ecp_sw_derive_y( const mbedtls_ecp_group *grp,
                                    const mbedtls_mpi *X,
                                    mbedtls_mpi *Y,
                                    int parity_bit )
{
    /* y^2 = x^3 + ax + b
     * sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4)
     *
     * Note: this method for extracting square root does not validate that w
     * was indeed a square so this function will return garbage in Y if X
     * does not correspond to a point on the curve.
     */

    /* Check prerequisite p = 3 mod 4 */
    if( mbedtls_mpi_get_bit( &grp->P, 0 ) != 1 ||
        mbedtls_mpi_get_bit( &grp->P, 1 ) != 1 )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

    int ret;
    mbedtls_mpi exp;
    mbedtls_mpi_init(&exp);

    /* use Y to store intermediate results */
    /* y^2 = x^3 + ax + b = (x^2 + a)x + b */
    /* x^2 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( Y, X, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( Y, Y, &grp->P ) );
    /* x^2 + a */
    if( !grp->A.p ) /* special case for A = -3; temporarily set exp = -3 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &exp, -3 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( Y, Y, grp->A.p ? &grp->A : &exp ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( Y, Y, &grp->P ) );
    /* (x^2 + a)x */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( Y, Y, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( Y, Y, &grp->P ) );
    /* (x^2 + a)x + b */
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( Y, Y, &grp->B ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( Y, Y, &grp->P ) );

    /* w = y^2 */ /* Y contains y^2 intermediate result */
    /* exp = ((p+1)/4) */
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &exp, &grp->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &exp, 2 ) );
    /* sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4) */
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( Y, Y /*y^2*/, &exp, &grp->P, NULL ) );

    /* check parity bit match or else invert Y */
    /* This quick inversion implementation is valid because Y != 0 for all
     * Short Weierstrass curves supported by mbedtls, as each supported curve
     * has an order that is a large prime, so each supported curve does not
     * have any point of order 2, and a point with Y == 0 would be of order 2 */
    if( mbedtls_mpi_get_bit( Y, 0 ) != parity_bit )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( Y, &grp->P, Y ) );

cleanup:

    mbedtls_mpi_free(&exp);
    return( ret );
}


int main(int argc,
         char *argv[])
{
    psa_key_id_t key;
    psa_status_t status;
    psa_key_attributes_t client_attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t derived_key[500] = {0};
    size_t derived_key_len;
    uint8_t output[65];
    size_t len;
    mbedtls_pk_context ctx_verify;
    mbedtls_ecp_point pt;

    psa_crypto_init();

    // First generate an ephemeral key for ECDH later

    psa_set_key_usage_flags( &client_attributes, PSA_KEY_USAGE_DERIVE );
    psa_set_key_algorithm( &client_attributes, PSA_ALG_ECDH );
    psa_set_key_type( &client_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );
    psa_set_key_bits( &client_attributes, 256 );

    /* Generate ephemeral key pair */
    status = psa_generate_key( &client_attributes, &key );
    if( status != PSA_SUCCESS )
    {
        printf("psa_generate_key() failed (%d).\r\n\n", status);
        return(-1);
    }

    // The compressed key
    uint8_t compKey[] = {0x02, 0x0B, 0x69, 0xFE, 0xB8, 0x01, 0xEB, 0x90, 0x33, 0x1E, 0xE2, 0xA6, 0x5C, 0xCB, 0xB8, 0x65, \
                         0xBD, 0x3D, 0x44, 0x3E, 0xDC, 0xDF, 0x2A, 0x11, 0x6D, 0x0E, 0x66, 0x7B, 0xC3, 0x46, 0x60, 0x93, \
                         0x8C};

    // Initialize stuff

    mbedtls_pk_init(&ctx_verify);

    status = mbedtls_pk_setup(&ctx_verify, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (status != PSA_SUCCESS)
    {
        printf("mbedtls_pk_setup() failed (%d).\r\n\n", status);
        return -1;
    }

    mbedtls_ecp_group_load(&mbedtls_pk_ec(ctx_verify)->grp, MBEDTLS_ECP_DP_SECP256R1);


    // Uncompress the key using https://github.com/mwarning/mbedtls_ecp_compression method

    status = mbedtls_ecp_decompress(&mbedtls_pk_ec(ctx_verify)->grp, compKey, sizeof(compKey), output, &len, sizeof(output));
    if (status != PSA_SUCCESS)
    {
        printf("mbedtls_ecp_decompress() failed (%d).\r\n\n", status);
        return -1;
    }

    printf("Uncompressed key according to mbedtls_ecp_decompress(): ");
    prv_logBuffer(output, len);

    // Use the uncompressed key to get a shared secret

    status = psa_raw_key_agreement( PSA_ALG_ECDH,
                                    key,
                                    output, len,
                                    derived_key, sizeof( derived_key ),
                                    &derived_key_len );
    
    if (status != PSA_SUCCESS)
    {
        printf("psa_raw_key_agreement() failed (%d).\r\n", status);
    }
    else
    {
        printf("psa_raw_key_agreement() result: ");
        prv_logBuffer(derived_key, derived_key_len);  
    }

    // Uncompress the key using https://github.com/Mbed-TLS/mbedtls/pull/6282

    mbedtls_ecp_point_init(&pt);
    mbedtls_mpi_read_binary_le( &(pt.X), compKey + 1, sizeof(compKey) - 1 );

    status = mbedtls_ecp_sw_derive_y(&mbedtls_pk_ec(ctx_verify)->grp, &(pt.X), &(pt.Y), 0);
    if (status != PSA_SUCCESS)
    {
        printf("mbedtls_ecp_sw_derive_y() failed (%d).\r\n\n", status);
        return -1;
    }

    output[0] = 0x04;
    memcpy(output + 1, pt.X.p, 32);
    memcpy(output + 33, pt.Y.p, 32);
    len = 65;

    printf("Uncompressed key according to mbedtls_ecp_sw_derive_y(): ");
    prv_logBuffer(output, len);

    // Use this other uncompressed key to get a shared secret

    status = psa_raw_key_agreement( PSA_ALG_ECDH,
                                    key,
                                    output, len,
                                    derived_key, sizeof( derived_key ),
                                    &derived_key_len );
    
    if (status != PSA_SUCCESS)
    {
        printf("psa_raw_key_agreement() failed (%d).\r\n\n", status);
    }
    else
    {
        printf("psa_raw_key_agreement() result:\r\n");
        prv_logBuffer(derived_key, derived_key_len);  
    }

    mbedtls_psa_crypto_free();

    return 0;
}
