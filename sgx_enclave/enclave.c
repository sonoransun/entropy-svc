/*
 * Minimal SGX enclave for mixrand entropy collection.
 *
 * This enclave exports a single ECALL that calls sgx_read_rand()
 * to generate random bytes using the SGX hardware RNG.
 *
 * Build requirements:
 *   - Intel SGX SDK installed (sgx_trts, sgx_tcrypto)
 *   - Sign with enclave signing key
 *
 * See Makefile for build instructions.
 */

#include <sgx_trts.h>
#include <stdint.h>
#include <string.h>

#include "enclave_t.h"  /* Generated from enclave.edl by sgx_edger8r */

/*
 * ecall_get_random - Generate random bytes inside the SGX enclave.
 *
 * @buf: Output buffer (allocated by untrusted caller, copied out by SGX)
 * @len: Number of random bytes to generate
 *
 * Returns 0 on success, -1 on failure.
 *
 * sgx_read_rand() uses the CPU hardware RNG (RDRAND/RDSEED) with
 * additional entropy conditioning provided by the SGX platform.
 */
int ecall_get_random(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return -1;

    sgx_status_t status = sgx_read_rand(buf, len);
    if (status != SGX_SUCCESS)
        return -1;

    return 0;
}
