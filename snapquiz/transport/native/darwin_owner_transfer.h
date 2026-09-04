#ifndef SNAPQUIZ_DARWIN_OWNER_TRANSFER_H
#define SNAPQUIZ_DARWIN_OWNER_TRANSFER_H

#include <stdint.h>

/*
 * Private C-to-C handoff contract shared by the numeric and TLS owners.
 *
 * The descriptor is an argument only to the native accept callback.  It is
 * never returned through the Python ABI.  An acceptor returning either of the
 * OWNED outcomes has already installed a durable recovery owner before it
 * returns; the numeric source must therefore relinquish close authority.
 */

#define SQ_OWNER_TRANSFER_CONTRACT_ABI 0x53515846u
#define SQ_OWNER_TRANSFER_CONTRACT_VERSION 1u

struct sq_owner_transfer_contract_descriptor {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
    uint32_t token_bytes;
    uint32_t owned_outcome_count;
    uint32_t raw_close_is_exactly_once;
    uint32_t descriptor_crosses_language_boundary;
};

_Static_assert(
    sizeof(struct sq_owner_transfer_contract_descriptor) == 32u,
    "numeric/TLS transfer contract size mismatch"
);

#define SQ_TRANSFER_NOT_ISSUED 1
#define SQ_TRANSFER_COMMITTED_OWNED 2
#define SQ_TRANSFER_UNCERTAIN_OWNED 3

typedef int32_t (*sq_transferred_raw_close_fn)(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *error_number
);

typedef int32_t (*sq_numeric_transfer_accept_fn)(
    void *context,
    int32_t descriptor,
    int32_t family,
    void *raw_close_context,
    sq_transferred_raw_close_fn raw_close,
    uint32_t connect_count,
    uint32_t peer_exact
);

#endif
