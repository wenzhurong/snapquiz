#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "darwin_owner_transfer.h"

/*
 * Opaque TLS-pair ownership cell for the W09 local/offline foundation.
 *
 * The production adapter will provide a reviewed native SSL/BIO vtable.  This
 * file deliberately imports no SSL implementation and performs no network
 * operation itself.  A caller allocates an inert publication buffer first,
 * then create_publish() creates the raw/TLS pair through the injected vtable
 * and commits the owner plus a native-CSPRNG bearer token before returning
 * across the language boundary.  Python never receives either native handle.
 *
 * A short publication mutex protects publication state and pins only.  No
 * injected callback runs while that mutex is held.  Owner operations are
 * serialized by a non-blocking atomic gate: contention returns EBUSY rather
 * than spinning while an external callback may be blocked or re-entrant.
 */

#define SQ_TLS_PUBLICATION_ABI 0x53515450u
#define SQ_TLS_VTABLE_ABI 0x53515456u
#define SQ_TLS_VTABLE_VERSION 1u
#define SQ_TLS_RESULT_ABI 0x53515452u
#define SQ_TLS_EVIDENCE_ABI 0x53515445u
#define SQ_TLS_SNAPSHOT_ABI 0x53515453u
#define SQ_TLS_TOKEN_BYTES 32u
#define SQ_TLS_POLICY_DIGEST_BYTES 32u
#define SQ_TLS_MAX_HOSTNAME_BYTES 253u
#define SQ_TLS_MAX_READ_BYTES 16384u
#define SQ_TLS_MAX_WRITE_BYTES (9u * 1024u * 1024u)
#define SQ_TLS_MAX_WAIT_NS 50000000ull
#define SQ_TLS_TRANSFER_CONTEXT_ABI 0x53515443u
#define SQ_TLS_ADOPT_VTABLE_ABI 0x53515441u
#define SQ_TLS_ADOPT_VTABLE_VERSION 1u
#define SQ_TLS_READINESS_ABI 0x53515457u

#define SQ_CALL_COMMITTED 0
#define SQ_CALL_NOT_ISSUED 1
#define SQ_CALL_AMBIGUOUS 2

#define SQ_IO_NONE 0u
#define SQ_IO_COMPLETE 1u
#define SQ_IO_WANT_READ 2u
#define SQ_IO_WANT_WRITE 3u
#define SQ_IO_DATA 4u
#define SQ_IO_EOF 5u
#define SQ_IO_NOT_ISSUED 6u
#define SQ_IO_AMBIGUOUS 7u

#define SQ_OWNER_ACTIVE 1u
#define SQ_OWNER_POISONED 2u
#define SQ_OWNER_CLOSED 3u

#define SQ_CLOSE_TERMINAL 1u
#define SQ_CLOSE_RETRYABLE 2u
#define SQ_CLOSE_UNCERTAIN 3u

#define SQ_RESOURCE_OPEN 1u
#define SQ_RESOURCE_ACTION_IN_FLIGHT 2u
#define SQ_RESOURCE_UNCERTAIN 3u
#define SQ_RESOURCE_CLOSED 4u

#define SQ_PUBLICATION_EMPTY 0u
#define SQ_PUBLICATION_CONSTRUCTING 1u
#define SQ_PUBLICATION_PUBLISHED 2u
#define SQ_PUBLICATION_RELEASED 3u
#define SQ_PUBLICATION_DEINITIALIZED 4u

#define SQ_POLICY_HOSTNAME_VERIFIED 0x01u
#define SQ_POLICY_ALPN_HTTP11 0x02u
#define SQ_POLICY_TLS12_OR_NEWER 0x04u

#define SQ_WAIT_READ 1u
#define SQ_WAIT_WRITE 2u
#define SQ_WAIT_READY 1u
#define SQ_WAIT_NOT_READY 2u
#define SQ_WAIT_NOT_ISSUED 3u
#define SQ_WAIT_AMBIGUOUS 4u

#define SQ_TRANSFER_CONTEXT_EMPTY 0u
#define SQ_TRANSFER_CONTEXT_READY 1u
#define SQ_TRANSFER_CONTEXT_IN_FLIGHT 2u
#define SQ_TRANSFER_CONTEXT_USED 3u
#define SQ_TRANSFER_CONTEXT_DEINITIALIZING 4u

typedef int32_t (*sq_tls_create_pair_fn)(
    void *, const uint8_t *, size_t, const uint8_t *, size_t,
    uintptr_t *, uintptr_t *
);
typedef int32_t (*sq_tls_handshake_fn)(void *, uintptr_t, uint32_t *);
typedef int32_t (*sq_tls_write_fn)(
    void *, uintptr_t, const uint8_t *, size_t, uint32_t *, size_t *
);
typedef int32_t (*sq_tls_read_fn)(
    void *, uintptr_t, uint8_t *, size_t, uint32_t *, size_t *
);
typedef int32_t (*sq_tls_negotiated_fn)(
    void *, uintptr_t, uint8_t *, size_t, size_t *,
    uint8_t *, size_t, size_t *
);
typedef int32_t (*sq_tls_close_fn)(void *, uintptr_t);
typedef int32_t (*sq_tls_observe_closed_fn)(void *, uintptr_t, uint32_t *);
typedef int32_t (*sq_tls_adopt_raw_fn)(
    void *, int32_t, const uint8_t *, size_t, const uint8_t *, size_t,
    uintptr_t *
);
typedef int32_t (*sq_tls_wait_ready_fn)(
    void *, uintptr_t, uint32_t, uint64_t, uint32_t *
);

struct sq_tls_vtable_header {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
};

struct sq_tls_vtable {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
    sq_tls_create_pair_fn create_pair;
    sq_tls_handshake_fn handshake;
    sq_tls_write_fn write;
    sq_tls_read_fn read;
    sq_tls_negotiated_fn negotiated;
    sq_tls_close_fn close_tls;
    sq_tls_close_fn close_raw;
    sq_tls_observe_closed_fn tls_is_closed;
    sq_tls_observe_closed_fn raw_is_closed;
};

struct sq_tls_adopt_vtable_header {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
};

struct sq_tls_adopt_vtable {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
    sq_tls_adopt_raw_fn adopt_raw;
    sq_tls_wait_ready_fn wait_ready;
};

struct sq_tls_token {
    uint8_t bytes[SQ_TLS_TOKEN_BYTES];
};

struct sq_tls_operation_result {
    uint32_t abi;
    uint32_t outcome;
    uint64_t operation_id;
    uint64_t count;
};

struct sq_tls_policy_evidence {
    uint32_t abi;
    uint32_t flags;
    uint32_t tls_version;
    uint32_t reserved;
    uint64_t hostname_digest;
    uint8_t policy_digest[SQ_TLS_POLICY_DIGEST_BYTES];
};

struct sq_tls_snapshot {
    uint32_t abi;
    uint32_t owner_state;
    uint32_t policy_attested;
    uint32_t reserved;
    uint64_t handshake_calls;
    uint64_t write_calls;
    uint64_t read_calls;
    uint64_t negotiated_calls;
    uint64_t tls_close_actions;
    uint64_t raw_close_actions;
    uint64_t last_handshake_operation_id;
    uint64_t last_write_operation_id;
    uint64_t last_read_operation_id;
};

struct sq_tls_readiness_snapshot {
    uint32_t abi;
    uint32_t transferred_raw;
    uint32_t last_direction;
    uint32_t reserved;
    uint64_t wait_calls;
    uint64_t last_max_wait_ns;
};

struct sq_tls_operation_ledger {
    uint64_t operation_id;
    uint64_t count;
    uint64_t input_digest;
    uint64_t input_length;
    uint32_t outcome;
};

struct sq_tls_owner {
    struct sq_tls_vtable vtable;
    void *context;
    uintptr_t raw_handle;
    uintptr_t tls_handle;
    struct sq_tls_token token;
    _Atomic uint32_t operation_gate;
    uint32_t state;
    uint32_t raw_close_state;
    uint32_t tls_close_state;
    uint32_t policy_attested;
    uint32_t tls_version;
    uint32_t construction_uncertain;
    uint32_t fail_next_write_allocation;
    uint64_t hostname_digest;
    uint8_t hostname[SQ_TLS_MAX_HOSTNAME_BYTES];
    size_t hostname_length;
    uint8_t policy_digest[SQ_TLS_POLICY_DIGEST_BYTES];
    struct sq_tls_operation_ledger handshake_ledger;
    struct sq_tls_operation_ledger write_ledger;
    struct sq_tls_operation_ledger read_ledger;
    uint8_t read_cache[SQ_TLS_MAX_READ_BYTES];
    uint8_t *write_cache;
    size_t write_cache_length;
    uint64_t handshake_calls;
    uint64_t write_calls;
    uint64_t read_calls;
    uint64_t negotiated_calls;
    uint64_t tls_close_actions;
    uint64_t raw_close_actions;
    uint32_t transferred_raw;
    int32_t transferred_descriptor;
    void *transferred_raw_context;
    sq_transferred_raw_close_fn transferred_raw_close;
    sq_tls_wait_ready_fn wait_ready;
    uint64_t wait_calls;
    uint64_t last_max_wait_ns;
    uint32_t last_wait_direction;
};

struct sq_tls_publication {
    _Atomic uint32_t abi;
    uint32_t reserved;
    pthread_mutex_t lifecycle_lock;
    _Atomic(struct sq_tls_owner *) owner;
    _Atomic uint64_t generation;
    _Atomic uint32_t state;
    uint32_t pins;
    struct sq_tls_owner owner_storage;
};

struct sq_tls_numeric_transfer_context {
    _Atomic uint32_t abi;
    _Atomic uint32_t state;
    struct sq_tls_publication *publication;
    struct sq_tls_vtable vtable;
    struct sq_tls_adopt_vtable adopt_vtable;
    void *context;
    uint8_t hostname[SQ_TLS_MAX_HOSTNAME_BYTES];
    size_t hostname_length;
    uint8_t policy_digest[SQ_TLS_POLICY_DIGEST_BYTES];
};

static _Atomic uint64_t sq_tls_global_generation = 1u;

_Static_assert(sizeof(struct sq_tls_token) == 32u, "token ABI mismatch");
_Static_assert(
    sizeof(struct sq_tls_operation_result) == 24u,
    "operation result ABI mismatch"
);
_Static_assert(
    sizeof(struct sq_tls_policy_evidence) == 56u,
    "policy evidence ABI mismatch"
);
_Static_assert(
    sizeof(struct sq_tls_snapshot) == 88u,
    "snapshot ABI mismatch"
);
_Static_assert(
    sizeof(struct sq_tls_readiness_snapshot) == 32u,
    "readiness snapshot ABI mismatch"
);

static uint64_t sq_tls_fnv1a(const uint8_t *data, size_t length) {
    uint64_t selected = UINT64_C(14695981039346656037);
    size_t index;
    for (index = 0u; index < length; ++index) {
        selected ^= (uint64_t)data[index];
        selected *= UINT64_C(1099511628211);
    }
    return selected;
}

static void sq_tls_clear_write_cache(struct sq_tls_owner *owner) {
    if (owner->write_cache != NULL) {
        memset(owner->write_cache, 0, owner->write_cache_length);
        free(owner->write_cache);
        owner->write_cache = NULL;
        owner->write_cache_length = 0u;
    }
}

static int sq_tls_is_alnum(uint8_t value) {
    return (value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
        (value >= (uint8_t)'0' && value <= (uint8_t)'9');
}

static int sq_tls_valid_hostname(const uint8_t *value, size_t length) {
    size_t index;
    size_t label_length = 0u;
    int only_ipv4_characters = 1;
    if (value == NULL || length == 0u || length > SQ_TLS_MAX_HOSTNAME_BYTES ||
        value[0] == (uint8_t)'.' || value[length - 1u] == (uint8_t)'.') {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        uint8_t current = value[index];
        if (current != (uint8_t)'.' &&
            !(current >= (uint8_t)'0' && current <= (uint8_t)'9')) {
            only_ipv4_characters = 0;
        }
        if (current == (uint8_t)'.') {
            if (label_length == 0u || label_length > 63u ||
                !sq_tls_is_alnum(value[index - 1u])) {
                return 0;
            }
            label_length = 0u;
            continue;
        }
        if (!(sq_tls_is_alnum(current) || current == (uint8_t)'-') ||
            (label_length == 0u && !sq_tls_is_alnum(current))) {
            return 0;
        }
        ++label_length;
        if (label_length > 63u) {
            return 0;
        }
    }
    return label_length > 0u && sq_tls_is_alnum(value[length - 1u]) &&
        !only_ipv4_characters;
}

static int sq_tls_vtable_valid(const struct sq_tls_vtable *vtable) {
    return vtable != NULL && vtable->abi == SQ_TLS_VTABLE_ABI &&
        vtable->size == sizeof(struct sq_tls_vtable) &&
        vtable->version == SQ_TLS_VTABLE_VERSION && vtable->reserved == 0u &&
        vtable->create_pair != NULL && vtable->handshake != NULL &&
        vtable->write != NULL && vtable->read != NULL &&
        vtable->negotiated != NULL && vtable->close_tls != NULL &&
        vtable->close_raw != NULL && vtable->tls_is_closed != NULL &&
        vtable->raw_is_closed != NULL;
}

static int sq_tls_vtable_header_valid(
    const struct sq_tls_vtable_header *header
) {
    return header->abi == SQ_TLS_VTABLE_ABI &&
        header->size == sizeof(struct sq_tls_vtable) &&
        header->version == SQ_TLS_VTABLE_VERSION && header->reserved == 0u;
}

static int sq_tls_adopt_vtable_valid(
    const struct sq_tls_adopt_vtable *vtable
) {
    return vtable != NULL && vtable->abi == SQ_TLS_ADOPT_VTABLE_ABI &&
        vtable->size == sizeof(struct sq_tls_adopt_vtable) &&
        vtable->version == SQ_TLS_ADOPT_VTABLE_VERSION &&
        vtable->reserved == 0u && vtable->adopt_raw != NULL &&
        vtable->wait_ready != NULL;
}

static int sq_tls_adopt_vtable_header_valid(
    const struct sq_tls_adopt_vtable_header *header
) {
    return header->abi == SQ_TLS_ADOPT_VTABLE_ABI &&
        header->size == sizeof(struct sq_tls_adopt_vtable) &&
        header->version == SQ_TLS_ADOPT_VTABLE_VERSION &&
        header->reserved == 0u;
}

static void sq_tls_make_token(struct sq_tls_owner *owner) {
    size_t index;
    uint8_t nonzero;
    do {
        arc4random_buf(owner->token.bytes, sizeof(owner->token.bytes));
        nonzero = 0u;
        for (index = 0u; index < sizeof(owner->token.bytes); ++index) {
            nonzero |= owner->token.bytes[index];
        }
    } while (nonzero == 0u);
}

static int sq_tls_token_equal(
    const struct sq_tls_token *left,
    const struct sq_tls_token *right
) {
    uint8_t difference = 0u;
    size_t index;
    if (left == NULL || right == NULL) {
        return 0;
    }
    for (index = 0u; index < SQ_TLS_TOKEN_BYTES; ++index) {
        difference |= left->bytes[index] ^ right->bytes[index];
    }
    return difference == 0u;
}

static int32_t sq_tls_publication_lock(
    struct sq_tls_publication *publication
) {
    int selected = pthread_mutex_lock(&publication->lifecycle_lock);
    return selected == 0 ? 0 : (int32_t)selected;
}

static void sq_tls_publication_unlock(
    struct sq_tls_publication *publication
) {
    (void)pthread_mutex_unlock(&publication->lifecycle_lock);
}

static int32_t sq_tls_pin_owner(
    struct sq_tls_publication *publication,
    const struct sq_tls_token *token,
    struct sq_tls_owner **selected
) {
    struct sq_tls_owner *owner;
    int32_t status;
    if (publication == NULL || token == NULL || selected == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI) {
        return EINVAL;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    if (atomic_load_explicit(
            &publication->abi, memory_order_relaxed
        ) != SQ_TLS_PUBLICATION_ABI ||
        atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_PUBLISHED) {
        sq_tls_publication_unlock(publication);
        return ESTALE;
    }
    owner = atomic_load_explicit(&publication->owner, memory_order_relaxed);
    if (owner == NULL || !sq_tls_token_equal(&owner->token, token)) {
        sq_tls_publication_unlock(publication);
        return ESTALE;
    }
    if (publication->pins == UINT32_MAX) {
        sq_tls_publication_unlock(publication);
        return EOVERFLOW;
    }
    ++publication->pins;
    *selected = owner;
    sq_tls_publication_unlock(publication);
    return 0;
}

static void sq_tls_unpin_owner(struct sq_tls_publication *publication) {
    if (sq_tls_publication_lock(publication) == 0) {
        if (publication->pins > 0u) {
            --publication->pins;
        }
        sq_tls_publication_unlock(publication);
    }
}

static int32_t sq_tls_begin_operation(
    struct sq_tls_publication *publication,
    const struct sq_tls_token *token,
    struct sq_tls_owner **selected
) {
    uint32_t expected = 0u;
    int32_t status = sq_tls_pin_owner(publication, token, selected);
    if (status != 0) {
        return status;
    }
    if (!atomic_compare_exchange_strong_explicit(
        &(*selected)->operation_gate,
        &expected,
        1u,
        memory_order_acq_rel,
        memory_order_acquire
    )) {
        sq_tls_unpin_owner(publication);
        return EBUSY;
    }
    return 0;
}

static void sq_tls_end_operation(
    struct sq_tls_publication *publication,
    struct sq_tls_owner *owner
) {
    atomic_store_explicit(&owner->operation_gate, 0u, memory_order_release);
    sq_tls_unpin_owner(publication);
}

static void sq_tls_result(
    struct sq_tls_operation_result *result,
    const struct sq_tls_operation_ledger *ledger
) {
    result->abi = SQ_TLS_RESULT_ABI;
    result->outcome = ledger->outcome;
    result->operation_id = ledger->operation_id;
    result->count = ledger->count;
}

static void sq_tls_publish_constructed_owner(
    struct sq_tls_publication *publication,
    struct sq_tls_owner *owner,
    uint64_t generation
) {
    /*
     * CONSTRUCTING is an exclusive publication claim.  Finalizing through the
     * atomic state avoids a second, fallible mutex acquisition after an
     * external constructor/adoption callback has acquired resources.  Readers
     * acquire publication->state before consuming owner storage.
     */
    atomic_store_explicit(&publication->owner, owner, memory_order_relaxed);
    atomic_store_explicit(
        &publication->generation, generation, memory_order_relaxed
    );
    atomic_store_explicit(
        &publication->state, SQ_PUBLICATION_PUBLISHED, memory_order_release
    );
}

static uint32_t sq_tls_call_failure_outcome(int32_t call_result) {
    return call_result == SQ_CALL_NOT_ISSUED ?
        SQ_IO_NOT_ISSUED : SQ_IO_AMBIGUOUS;
}

size_t sq_tls_publication_size(void) {
    return sizeof(struct sq_tls_publication);
}

size_t sq_tls_vtable_size(void) {
    return sizeof(struct sq_tls_vtable);
}

size_t sq_tls_adopt_vtable_size(void) {
    return sizeof(struct sq_tls_adopt_vtable);
}

size_t sq_tls_numeric_transfer_context_size(void) {
    return sizeof(struct sq_tls_numeric_transfer_context);
}

uint32_t sq_tls_transfer_contract_abi(void) {
    return SQ_OWNER_TRANSFER_CONTRACT_ABI;
}

uint32_t sq_tls_transfer_contract_size(void) {
    return (uint32_t)sizeof(struct sq_owner_transfer_contract_descriptor);
}

uint32_t sq_tls_transfer_contract_version(void) {
    return SQ_OWNER_TRANSFER_CONTRACT_VERSION;
}

int32_t sq_tls_publication_init(void *storage, size_t storage_size) {
    struct sq_tls_publication *publication;
    int selected;
    if (storage == NULL || storage_size < sizeof(struct sq_tls_publication)) {
        return EINVAL;
    }
    publication = (struct sq_tls_publication *)storage;
    memset(publication, 0, sizeof(*publication));
    selected = pthread_mutex_init(&publication->lifecycle_lock, NULL);
    if (selected != 0) {
        return (int32_t)selected;
    }
    atomic_init(&publication->owner, NULL);
    atomic_init(&publication->generation, 0u);
    atomic_init(&publication->state, SQ_PUBLICATION_EMPTY);
    atomic_init(&publication->abi, SQ_TLS_PUBLICATION_ABI);
    return 0;
}

int32_t sq_tls_numeric_transfer_context_init(
    void *storage,
    size_t storage_size,
    void *publication_storage,
    const struct sq_tls_vtable *vtable,
    const struct sq_tls_adopt_vtable *adopt_vtable,
    void *context,
    const uint8_t *hostname,
    size_t hostname_length,
    const uint8_t policy_digest[SQ_TLS_POLICY_DIGEST_BYTES]
) {
    struct sq_tls_numeric_transfer_context *transfer;
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)publication_storage;
    struct sq_tls_vtable_header vtable_header;
    struct sq_tls_adopt_vtable_header adopt_header;
    int32_t status;
    if (storage == NULL ||
        storage_size < sizeof(struct sq_tls_numeric_transfer_context) ||
        publication == NULL || vtable == NULL || adopt_vtable == NULL ||
        policy_digest == NULL ||
        !sq_tls_valid_hostname(hostname, hostname_length) ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI) {
        return EINVAL;
    }
    memcpy(&vtable_header, vtable, sizeof(vtable_header));
    memcpy(&adopt_header, adopt_vtable, sizeof(adopt_header));
    if (!sq_tls_vtable_header_valid(&vtable_header) ||
        !sq_tls_adopt_vtable_header_valid(&adopt_header)) {
        return EINVAL;
    }
    transfer = (struct sq_tls_numeric_transfer_context *)storage;
    if (atomic_load_explicit(&transfer->abi, memory_order_acquire) != 0u) {
        return EBUSY;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    if (atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_EMPTY ||
        atomic_load_explicit(&publication->owner, memory_order_relaxed) != NULL) {
        sq_tls_publication_unlock(publication);
        return EBUSY;
    }
    sq_tls_publication_unlock(publication);

    memset(transfer, 0, sizeof(*transfer));
    memcpy(&transfer->vtable, vtable, sizeof(transfer->vtable));
    memcpy(
        &transfer->adopt_vtable,
        adopt_vtable,
        sizeof(transfer->adopt_vtable)
    );
    if (!sq_tls_vtable_valid(&transfer->vtable) ||
        !sq_tls_adopt_vtable_valid(&transfer->adopt_vtable)) {
        memset(transfer, 0, sizeof(*transfer));
        return EINVAL;
    }
    transfer->publication = publication;
    transfer->context = context;
    memcpy(transfer->hostname, hostname, hostname_length);
    transfer->hostname_length = hostname_length;
    memcpy(
        transfer->policy_digest,
        policy_digest,
        SQ_TLS_POLICY_DIGEST_BYTES
    );
    atomic_init(&transfer->state, SQ_TRANSFER_CONTEXT_READY);
    atomic_init(&transfer->abi, SQ_TLS_TRANSFER_CONTEXT_ABI);
    return 0;
}

int32_t sq_tls_accept_numeric_transfer(
    void *context,
    int32_t descriptor,
    int32_t family,
    void *raw_close_context,
    sq_transferred_raw_close_fn raw_close,
    uint32_t connect_count,
    uint32_t peer_exact
) {
    struct sq_tls_numeric_transfer_context *transfer =
        (struct sq_tls_numeric_transfer_context *)context;
    struct sq_tls_publication *publication;
    struct sq_tls_owner *owner;
    uint32_t expected_state = SQ_TRANSFER_CONTEXT_READY;
    int32_t call_result;
    int32_t status;
    int valid_tls;
    uint64_t generation;

    if (transfer == NULL || descriptor < 0 ||
        (family != AF_INET && family != AF_INET6) || raw_close == NULL ||
        connect_count != 1u || peer_exact != 1u ||
        atomic_load_explicit(
            &transfer->abi, memory_order_acquire
        ) != SQ_TLS_TRANSFER_CONTEXT_ABI ||
        !atomic_compare_exchange_strong_explicit(
            &transfer->state,
            &expected_state,
            SQ_TRANSFER_CONTEXT_IN_FLIGHT,
            memory_order_acq_rel,
            memory_order_acquire
        )) {
        return SQ_TRANSFER_NOT_ISSUED;
    }
    publication = transfer->publication;
    if (publication == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI ||
        !sq_tls_vtable_valid(&transfer->vtable) ||
        !sq_tls_adopt_vtable_valid(&transfer->adopt_vtable) ||
        !sq_tls_valid_hostname(
            transfer->hostname, transfer->hostname_length
        )) {
        atomic_store_explicit(
            &transfer->state, SQ_TRANSFER_CONTEXT_USED, memory_order_release
        );
        return SQ_TRANSFER_NOT_ISSUED;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        atomic_store_explicit(
            &transfer->state, SQ_TRANSFER_CONTEXT_USED, memory_order_release
        );
        return SQ_TRANSFER_NOT_ISSUED;
    }
    if (atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_EMPTY ||
        atomic_load_explicit(&publication->owner, memory_order_relaxed) != NULL) {
        sq_tls_publication_unlock(publication);
        atomic_store_explicit(
            &transfer->state, SQ_TRANSFER_CONTEXT_USED, memory_order_release
        );
        return SQ_TRANSFER_NOT_ISSUED;
    }
    atomic_store_explicit(
        &publication->state,
        SQ_PUBLICATION_CONSTRUCTING,
        memory_order_release
    );
    sq_tls_publication_unlock(publication);

    owner = &publication->owner_storage;
    memset(owner, 0, sizeof(*owner));
    memcpy(&owner->vtable, &transfer->vtable, sizeof(owner->vtable));
    owner->context = transfer->context;
    owner->transferred_raw = 1u;
    owner->transferred_descriptor = descriptor;
    owner->transferred_raw_context = raw_close_context;
    owner->transferred_raw_close = raw_close;
    owner->wait_ready = transfer->adopt_vtable.wait_ready;
    owner->raw_handle = 1u; /* Native-private presence marker, never the fd. */
    memcpy(
        owner->hostname,
        transfer->hostname,
        transfer->hostname_length
    );
    owner->hostname_length = transfer->hostname_length;
    memcpy(
        owner->policy_digest,
        transfer->policy_digest,
        SQ_TLS_POLICY_DIGEST_BYTES
    );
    owner->hostname_digest = sq_tls_fnv1a(
        transfer->hostname,
        transfer->hostname_length
    );
    atomic_init(&owner->operation_gate, 0u);

    call_result = transfer->adopt_vtable.adopt_raw(
        owner->context,
        descriptor,
        owner->hostname,
        owner->hostname_length,
        (const uint8_t *)"http/1.1",
        8u,
        &owner->tls_handle
    );
    if (call_result == SQ_CALL_NOT_ISSUED && owner->tls_handle == 0u) {
        memset(owner, 0, sizeof(*owner));
        atomic_store_explicit(
            &publication->state, SQ_PUBLICATION_EMPTY, memory_order_release
        );
        atomic_store_explicit(
            &transfer->state, SQ_TRANSFER_CONTEXT_USED, memory_order_release
        );
        return SQ_TRANSFER_NOT_ISSUED;
    }

    valid_tls = call_result == SQ_CALL_COMMITTED && owner->tls_handle != 0u;
    owner->construction_uncertain = valid_tls ? 0u : 1u;
    owner->raw_close_state = SQ_RESOURCE_OPEN;
    owner->tls_close_state = owner->tls_handle == 0u ?
        SQ_RESOURCE_CLOSED : SQ_RESOURCE_OPEN;
    owner->state = valid_tls ? SQ_OWNER_ACTIVE : SQ_OWNER_POISONED;
    generation = atomic_fetch_add_explicit(
        &sq_tls_global_generation, 1u, memory_order_relaxed
    );
    if (generation == 0u) {
        generation = atomic_fetch_add_explicit(
            &sq_tls_global_generation, 1u, memory_order_relaxed
        );
    }
    sq_tls_make_token(owner);

    sq_tls_publish_constructed_owner(publication, owner, generation);
    atomic_store_explicit(
        &transfer->state, SQ_TRANSFER_CONTEXT_USED, memory_order_release
    );
    return valid_tls ?
        SQ_TRANSFER_COMMITTED_OWNED : SQ_TRANSFER_UNCERTAIN_OWNED;
}

int32_t sq_tls_numeric_transfer_context_deinit(void *storage) {
    struct sq_tls_numeric_transfer_context *transfer =
        (struct sq_tls_numeric_transfer_context *)storage;
    uint32_t expected;
    if (transfer == NULL ||
        atomic_load_explicit(
            &transfer->abi, memory_order_acquire
        ) != SQ_TLS_TRANSFER_CONTEXT_ABI) {
        return EINVAL;
    }
    expected = SQ_TRANSFER_CONTEXT_READY;
    if (!atomic_compare_exchange_strong_explicit(
            &transfer->state,
            &expected,
            SQ_TRANSFER_CONTEXT_DEINITIALIZING,
            memory_order_acq_rel,
            memory_order_acquire
        )) {
        expected = SQ_TRANSFER_CONTEXT_USED;
        if (!atomic_compare_exchange_strong_explicit(
                &transfer->state,
                &expected,
                SQ_TRANSFER_CONTEXT_DEINITIALIZING,
                memory_order_acq_rel,
                memory_order_acquire
            )) {
            return expected == SQ_TRANSFER_CONTEXT_IN_FLIGHT ? EBUSY : EINVAL;
        }
    }
    transfer->publication = NULL;
    memset(&transfer->vtable, 0, sizeof(transfer->vtable));
    memset(&transfer->adopt_vtable, 0, sizeof(transfer->adopt_vtable));
    transfer->context = NULL;
    memset(transfer->hostname, 0, sizeof(transfer->hostname));
    transfer->hostname_length = 0u;
    memset(transfer->policy_digest, 0, sizeof(transfer->policy_digest));
    atomic_store_explicit(
        &transfer->state, SQ_TRANSFER_CONTEXT_EMPTY, memory_order_release
    );
    /* Publish ABI zero last so a later initializer cannot race the clearing. */
    atomic_store_explicit(&transfer->abi, 0u, memory_order_release);
    return 0;
}

int32_t sq_tls_create_publish(
    void *storage,
    const struct sq_tls_vtable *vtable,
    void *context,
    const uint8_t *hostname,
    size_t hostname_length,
    const uint8_t policy_digest[SQ_TLS_POLICY_DIGEST_BYTES]
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    struct sq_tls_vtable_header vtable_header;
    struct sq_tls_vtable checked_vtable;
    int32_t call_result;
    int32_t status;
    int valid_pair;
    uint64_t generation;

    if (publication == NULL || vtable == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI || policy_digest == NULL ||
        !sq_tls_valid_hostname(hostname, hostname_length)) {
        return EINVAL;
    }
    memcpy(&vtable_header, vtable, sizeof(vtable_header));
    if (!sq_tls_vtable_header_valid(&vtable_header)) {
        return EINVAL;
    }
    memcpy(&checked_vtable, vtable, sizeof(checked_vtable));
    if (!sq_tls_vtable_valid(&checked_vtable)) {
        return EINVAL;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    if (atomic_load_explicit(
            &publication->abi, memory_order_relaxed
        ) != SQ_TLS_PUBLICATION_ABI) {
        sq_tls_publication_unlock(publication);
        return EINVAL;
    }
    if (atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_EMPTY) {
        sq_tls_publication_unlock(publication);
        return EBUSY;
    }
    atomic_store_explicit(
        &publication->state,
        SQ_PUBLICATION_CONSTRUCTING,
        memory_order_release
    );
    sq_tls_publication_unlock(publication);

    owner = &publication->owner_storage;
    memset(owner, 0, sizeof(*owner));
    memcpy(&owner->vtable, &checked_vtable, sizeof(checked_vtable));
    owner->context = context;
    memcpy(owner->hostname, hostname, hostname_length);
    owner->hostname_length = hostname_length;
    memcpy(owner->policy_digest, policy_digest, SQ_TLS_POLICY_DIGEST_BYTES);
    owner->hostname_digest = sq_tls_fnv1a(hostname, hostname_length);
    atomic_init(&owner->operation_gate, 0u);

    call_result = owner->vtable.create_pair(
        owner->context,
        owner->hostname,
        owner->hostname_length,
        (const uint8_t *)"http/1.1",
        8u,
        &owner->raw_handle,
        &owner->tls_handle
    );
    if (call_result == SQ_CALL_NOT_ISSUED && owner->raw_handle == 0u &&
        owner->tls_handle == 0u) {
        memset(owner, 0, sizeof(*owner));
        atomic_store_explicit(
            &publication->state, SQ_PUBLICATION_EMPTY, memory_order_release
        );
        return EAGAIN;
    }

    valid_pair = call_result == SQ_CALL_COMMITTED &&
        owner->raw_handle != 0u && owner->tls_handle != 0u &&
        owner->raw_handle != owner->tls_handle;
    owner->construction_uncertain = valid_pair ? 0u : 1u;
    if (owner->raw_handle != 0u && owner->raw_handle == owner->tls_handle) {
        /* One aliased handle receives exactly one close action. */
        owner->tls_handle = 0u;
    }
    owner->raw_close_state = owner->raw_handle == 0u ?
        SQ_RESOURCE_CLOSED : SQ_RESOURCE_OPEN;
    owner->tls_close_state = owner->tls_handle == 0u ?
        SQ_RESOURCE_CLOSED : SQ_RESOURCE_OPEN;
    owner->state = valid_pair ? SQ_OWNER_ACTIVE : SQ_OWNER_POISONED;
    generation = atomic_fetch_add_explicit(
        &sq_tls_global_generation, 1u, memory_order_relaxed
    );
    if (generation == 0u) {
        generation = atomic_fetch_add_explicit(
            &sq_tls_global_generation, 1u, memory_order_relaxed
        );
    }
    sq_tls_make_token(owner);

    sq_tls_publish_constructed_owner(publication, owner, generation);
    return 0;
}

int32_t sq_tls_snapshot_token(
    void *storage,
    struct sq_tls_token *token
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t status;
    if (publication == NULL || token == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI) {
        return EINVAL;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    if (atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_PUBLISHED) {
        sq_tls_publication_unlock(publication);
        return ENOENT;
    }
    owner = atomic_load_explicit(&publication->owner, memory_order_relaxed);
    if (owner == NULL) {
        sq_tls_publication_unlock(publication);
        return ENOENT;
    }
    memcpy(token, &owner->token, sizeof(*token));
    sq_tls_publication_unlock(publication);
    return 0;
}

int32_t sq_tls_handshake(
    void *storage,
    const struct sq_tls_token *token,
    uint64_t operation_id,
    struct sq_tls_operation_result *result
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    struct sq_tls_operation_ledger *ledger;
    uint32_t outcome = SQ_IO_NONE;
    int32_t status;
    if (operation_id == 0u || result == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state == SQ_OWNER_CLOSED) {
        sq_tls_end_operation(publication, owner);
        return EPERM;
    }
    ledger = &owner->handshake_ledger;
    if (ledger->operation_id == operation_id) {
        sq_tls_result(result, ledger);
        sq_tls_end_operation(publication, owner);
        return 0;
    }
    if (ledger->operation_id >= operation_id || owner->state != SQ_OWNER_ACTIVE) {
        status = owner->state == SQ_OWNER_ACTIVE ? EALREADY : EPERM;
        sq_tls_end_operation(publication, owner);
        return status;
    }
    ledger->operation_id = operation_id;
    ledger->count = 0u;
    ledger->outcome = SQ_IO_AMBIGUOUS;
    ++owner->handshake_calls;
    status = owner->vtable.handshake(
        owner->context, owner->tls_handle, &outcome
    );
    if (status == SQ_CALL_COMMITTED &&
        (outcome == SQ_IO_COMPLETE || outcome == SQ_IO_WANT_READ ||
         outcome == SQ_IO_WANT_WRITE)) {
        ledger->outcome = outcome;
    } else {
        ledger->outcome = sq_tls_call_failure_outcome(status);
        if (ledger->outcome == SQ_IO_AMBIGUOUS) {
            owner->state = SQ_OWNER_POISONED;
        }
    }
    sq_tls_result(result, ledger);
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_wait_ready(
    void *storage,
    const struct sq_tls_token *token,
    uint32_t direction,
    uint64_t max_wait_ns,
    uint32_t *wait_outcome
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    uint32_t ready = 0u;
    int32_t call_result;
    int32_t status;
    if ((direction != SQ_WAIT_READ && direction != SQ_WAIT_WRITE) ||
        max_wait_ns == 0u || max_wait_ns > SQ_TLS_MAX_WAIT_NS ||
        wait_outcome == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state != SQ_OWNER_ACTIVE || owner->transferred_raw != 1u ||
        owner->wait_ready == NULL) {
        sq_tls_end_operation(publication, owner);
        return EPERM;
    }
    ++owner->wait_calls;
    owner->last_max_wait_ns = max_wait_ns;
    owner->last_wait_direction = direction;
    call_result = owner->wait_ready(
        owner->context,
        owner->tls_handle,
        direction,
        max_wait_ns,
        &ready
    );
    if (call_result == SQ_CALL_COMMITTED && ready <= 1u) {
        *wait_outcome = ready == 1u ? SQ_WAIT_READY : SQ_WAIT_NOT_READY;
    } else if (call_result == SQ_CALL_NOT_ISSUED && ready == 0u) {
        *wait_outcome = SQ_WAIT_NOT_ISSUED;
    } else {
        *wait_outcome = SQ_WAIT_AMBIGUOUS;
        owner->state = SQ_OWNER_POISONED;
    }
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_write(
    void *storage,
    const struct sq_tls_token *token,
    uint64_t operation_id,
    const uint8_t *data,
    size_t length,
    struct sq_tls_operation_result *result
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    struct sq_tls_operation_ledger *ledger;
    uint8_t *new_cache;
    uint8_t *old_cache;
    size_t old_cache_length;
    uint64_t input_digest;
    uint32_t outcome = SQ_IO_NONE;
    size_t count = 0u;
    int32_t status;
    if (operation_id == 0u || data == NULL || length == 0u ||
        length > SQ_TLS_MAX_WRITE_BYTES || result == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state == SQ_OWNER_CLOSED) {
        sq_tls_end_operation(publication, owner);
        return EPERM;
    }
    ledger = &owner->write_ledger;
    if (ledger->operation_id == operation_id) {
        input_digest = sq_tls_fnv1a(data, length);
        if (ledger->input_length != length ||
            ledger->input_digest != input_digest ||
            owner->write_cache_length != length ||
            owner->write_cache == NULL ||
            memcmp(owner->write_cache, data, length) != 0) {
            sq_tls_end_operation(publication, owner);
            return EBADMSG;
        }
        sq_tls_result(result, ledger);
        sq_tls_end_operation(publication, owner);
        return 0;
    }
    if (ledger->operation_id >= operation_id || owner->state != SQ_OWNER_ACTIVE) {
        status = owner->state == SQ_OWNER_ACTIVE ? EALREADY : EPERM;
        sq_tls_end_operation(publication, owner);
        return status;
    }
    if (owner->fail_next_write_allocation != 0u) {
        owner->fail_next_write_allocation = 0u;
        sq_tls_end_operation(publication, owner);
        return ENOMEM;
    }
    new_cache = (uint8_t *)malloc(length);
    if (new_cache == NULL) {
        sq_tls_end_operation(publication, owner);
        return ENOMEM;
    }
    memcpy(new_cache, data, length);
    input_digest = sq_tls_fnv1a(new_cache, length);

    old_cache = owner->write_cache;
    old_cache_length = owner->write_cache_length;
    owner->write_cache = new_cache;
    owner->write_cache_length = length;
    ledger->operation_id = operation_id;
    ledger->input_length = length;
    ledger->input_digest = input_digest;
    ledger->count = 0u;
    ledger->outcome = SQ_IO_AMBIGUOUS;
    if (old_cache != NULL) {
        memset(old_cache, 0, old_cache_length);
        free(old_cache);
    }

    ++owner->write_calls;
    status = owner->vtable.write(
        owner->context,
        owner->tls_handle,
        owner->write_cache,
        length,
        &outcome,
        &count
    );
    if (status == SQ_CALL_COMMITTED) {
        if (outcome == SQ_IO_COMPLETE && count > 0u && count <= length) {
            ledger->outcome = SQ_IO_COMPLETE;
            ledger->count = (uint64_t)count;
        } else if ((outcome == SQ_IO_WANT_READ ||
                    outcome == SQ_IO_WANT_WRITE) && count == 0u) {
            ledger->outcome = outcome;
        } else {
            ledger->outcome = SQ_IO_AMBIGUOUS;
            owner->state = SQ_OWNER_POISONED;
        }
    } else if (status == SQ_CALL_NOT_ISSUED && count == 0u) {
        ledger->outcome = SQ_IO_NOT_ISSUED;
    } else {
        ledger->outcome = SQ_IO_AMBIGUOUS;
        owner->state = SQ_OWNER_POISONED;
    }
    sq_tls_result(result, ledger);
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_read(
    void *storage,
    const struct sq_tls_token *token,
    uint64_t operation_id,
    size_t maximum,
    uint8_t *output,
    size_t output_capacity,
    struct sq_tls_operation_result *result
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    struct sq_tls_operation_ledger *ledger;
    uint32_t outcome = SQ_IO_NONE;
    size_t count = 0u;
    int32_t status;
    if (operation_id == 0u || maximum == 0u ||
        maximum > SQ_TLS_MAX_READ_BYTES || output == NULL ||
        output_capacity < maximum || result == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state == SQ_OWNER_CLOSED) {
        sq_tls_end_operation(publication, owner);
        return EPERM;
    }
    ledger = &owner->read_ledger;
    if (ledger->operation_id == operation_id) {
        if (ledger->input_length != maximum) {
            sq_tls_end_operation(publication, owner);
            return EBADMSG;
        }
        if (ledger->count > output_capacity) {
            sq_tls_end_operation(publication, owner);
            return ENOBUFS;
        }
        if (ledger->outcome == SQ_IO_DATA && ledger->count > 0u) {
            memcpy(output, owner->read_cache, (size_t)ledger->count);
        }
        sq_tls_result(result, ledger);
        sq_tls_end_operation(publication, owner);
        return 0;
    }
    if (ledger->operation_id >= operation_id || owner->state != SQ_OWNER_ACTIVE) {
        status = owner->state == SQ_OWNER_ACTIVE ? EALREADY : EPERM;
        sq_tls_end_operation(publication, owner);
        return status;
    }
    ledger->operation_id = operation_id;
    ledger->input_length = maximum;
    ledger->count = 0u;
    ledger->outcome = SQ_IO_AMBIGUOUS;
    ++owner->read_calls;
    memset(owner->read_cache, 0, maximum);
    status = owner->vtable.read(
        owner->context,
        owner->tls_handle,
        owner->read_cache,
        maximum,
        &outcome,
        &count
    );
    if (status == SQ_CALL_COMMITTED) {
        if (outcome == SQ_IO_DATA && count > 0u && count <= maximum) {
            ledger->outcome = SQ_IO_DATA;
            ledger->count = (uint64_t)count;
        } else if (outcome == SQ_IO_EOF && count == 0u) {
            ledger->outcome = SQ_IO_EOF;
        } else if ((outcome == SQ_IO_WANT_READ ||
                    outcome == SQ_IO_WANT_WRITE) && count == 0u) {
            ledger->outcome = outcome;
        } else {
            ledger->outcome = SQ_IO_AMBIGUOUS;
            owner->state = SQ_OWNER_POISONED;
        }
    } else if (status == SQ_CALL_NOT_ISSUED && count == 0u) {
        ledger->outcome = SQ_IO_NOT_ISSUED;
    } else {
        ledger->outcome = SQ_IO_AMBIGUOUS;
        owner->state = SQ_OWNER_POISONED;
    }
    if (ledger->outcome == SQ_IO_DATA && ledger->count > 0u) {
        memcpy(output, owner->read_cache, (size_t)ledger->count);
    }
    sq_tls_result(result, ledger);
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_attest_policy(
    void *storage,
    const struct sq_tls_token *token,
    struct sq_tls_policy_evidence *evidence
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    uint8_t alpn[16];
    uint8_t version[16];
    size_t alpn_length = 0u;
    size_t version_length = 0u;
    int32_t call_result;
    int32_t status;
    if (evidence == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->policy_attested == 0u) {
        if (owner->state != SQ_OWNER_ACTIVE ||
            owner->handshake_ledger.outcome != SQ_IO_COMPLETE) {
            sq_tls_end_operation(publication, owner);
            return EPERM;
        }
        memset(alpn, 0, sizeof(alpn));
        memset(version, 0, sizeof(version));
        ++owner->negotiated_calls;
        call_result = owner->vtable.negotiated(
            owner->context,
            owner->tls_handle,
            alpn,
            sizeof(alpn),
            &alpn_length,
            version,
            sizeof(version),
            &version_length
        );
        if (call_result != SQ_CALL_COMMITTED ||
            alpn_length != 8u || memcmp(alpn, "http/1.1", 8u) != 0) {
            owner->state = SQ_OWNER_POISONED;
            sq_tls_end_operation(publication, owner);
            return EPROTO;
        }
        if (version_length == 7u &&
            memcmp(version, "TLSv1.2", 7u) == 0) {
            owner->tls_version = 12u;
        } else if (version_length == 7u &&
            memcmp(version, "TLSv1.3", 7u) == 0) {
            owner->tls_version = 13u;
        } else {
            owner->state = SQ_OWNER_POISONED;
            sq_tls_end_operation(publication, owner);
            return EPROTO;
        }
        owner->policy_attested = 1u;
    }
    memset(evidence, 0, sizeof(*evidence));
    evidence->abi = SQ_TLS_EVIDENCE_ABI;
    evidence->flags = SQ_POLICY_HOSTNAME_VERIFIED |
        SQ_POLICY_ALPN_HTTP11 | SQ_POLICY_TLS12_OR_NEWER;
    evidence->tls_version = owner->tls_version;
    evidence->hostname_digest = owner->hostname_digest;
    memcpy(
        evidence->policy_digest,
        owner->policy_digest,
        SQ_TLS_POLICY_DIGEST_BYTES
    );
    sq_tls_end_operation(publication, owner);
    return 0;
}

static int32_t sq_tls_observe_resource(
    struct sq_tls_owner *owner,
    uintptr_t handle,
    sq_tls_observe_closed_fn observe,
    uint32_t *resource_state
) {
    uint32_t closed = 0u;
    int32_t result;
    if (*resource_state == SQ_RESOURCE_CLOSED || handle == 0u) {
        *resource_state = SQ_RESOURCE_CLOSED;
        return 0;
    }
    result = observe(owner->context, handle, &closed);
    if (result == SQ_CALL_COMMITTED && closed == 1u) {
        *resource_state = SQ_RESOURCE_CLOSED;
        return 0;
    }
    return EAGAIN;
}

static int32_t sq_tls_close_resource(
    struct sq_tls_owner *owner,
    uintptr_t handle,
    sq_tls_close_fn close_action,
    sq_tls_observe_closed_fn observe,
    uint32_t *resource_state,
    uint64_t *action_count
) {
    int32_t result;
    if (sq_tls_observe_resource(owner, handle, observe, resource_state) == 0) {
        return 0;
    }
    if (*resource_state == SQ_RESOURCE_ACTION_IN_FLIGHT ||
        *resource_state == SQ_RESOURCE_UNCERTAIN) {
        *resource_state = SQ_RESOURCE_UNCERTAIN;
        return EBUSY;
    }
    if (*resource_state != SQ_RESOURCE_OPEN) {
        return EINVAL;
    }
    *resource_state = SQ_RESOURCE_ACTION_IN_FLIGHT;
    ++(*action_count);
    result = close_action(owner->context, handle);
    if (result == SQ_CALL_NOT_ISSUED) {
        *resource_state = SQ_RESOURCE_OPEN;
        return EAGAIN;
    }
    *resource_state = SQ_RESOURCE_UNCERTAIN;
    if (sq_tls_observe_resource(owner, handle, observe, resource_state) == 0) {
        return 0;
    }
    return EBUSY;
}

static int32_t sq_tls_close_transferred_raw(
    struct sq_tls_owner *owner
) {
    int32_t certainty;
    int32_t result = -1;
    int32_t error_number = 0;
    if (owner->raw_close_state == SQ_RESOURCE_CLOSED) {
        return 0;
    }
    if (owner->raw_close_state == SQ_RESOURCE_ACTION_IN_FLIGHT ||
        owner->raw_close_state == SQ_RESOURCE_UNCERTAIN) {
        owner->raw_close_state = SQ_RESOURCE_UNCERTAIN;
        return EBUSY;
    }
    if (owner->raw_close_state != SQ_RESOURCE_OPEN ||
        owner->transferred_raw_close == NULL ||
        owner->transferred_descriptor < 0) {
        return EINVAL;
    }
    owner->raw_close_state = SQ_RESOURCE_ACTION_IN_FLIGHT;
    ++owner->raw_close_actions;
    certainty = owner->transferred_raw_close(
        owner->transferred_raw_context,
        owner->transferred_descriptor,
        &result,
        &error_number
    );
    owner->transferred_descriptor = -1;
    if (certainty == SQ_CALL_COMMITTED && result == 0) {
        owner->raw_close_state = SQ_RESOURCE_CLOSED;
        return 0;
    }
    owner->raw_close_state = SQ_RESOURCE_UNCERTAIN;
    return EBUSY;
}

int32_t sq_tls_close(
    void *storage,
    const struct sq_tls_token *token,
    uint32_t *close_outcome
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t tls_result;
    int32_t raw_result;
    int32_t status;
    if (close_outcome == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state == SQ_OWNER_CLOSED) {
        *close_outcome = SQ_CLOSE_TERMINAL;
        sq_tls_end_operation(publication, owner);
        return 0;
    }
    tls_result = sq_tls_close_resource(
        owner,
        owner->tls_handle,
        owner->vtable.close_tls,
        owner->vtable.tls_is_closed,
        &owner->tls_close_state,
        &owner->tls_close_actions
    );
    if (owner->transferred_raw == 1u) {
        raw_result = sq_tls_close_transferred_raw(owner);
    } else {
        raw_result = sq_tls_close_resource(
            owner,
            owner->raw_handle,
            owner->vtable.close_raw,
            owner->vtable.raw_is_closed,
            &owner->raw_close_state,
            &owner->raw_close_actions
        );
    }
    if (owner->tls_close_state == SQ_RESOURCE_CLOSED &&
        owner->raw_close_state == SQ_RESOURCE_CLOSED) {
        owner->tls_handle = 0u;
        owner->raw_handle = 0u;
        memset(owner->read_cache, 0, sizeof(owner->read_cache));
        sq_tls_clear_write_cache(owner);
        if (owner->construction_uncertain != 0u) {
            owner->state = SQ_OWNER_POISONED;
            *close_outcome = SQ_CLOSE_UNCERTAIN;
        } else {
            owner->state = SQ_OWNER_CLOSED;
            *close_outcome = SQ_CLOSE_TERMINAL;
        }
    } else if (tls_result == EBUSY || raw_result == EBUSY) {
        *close_outcome = SQ_CLOSE_UNCERTAIN;
    } else if (tls_result == EAGAIN || raw_result == EAGAIN) {
        *close_outcome = SQ_CLOSE_RETRYABLE;
    } else {
        *close_outcome = SQ_CLOSE_UNCERTAIN;
    }
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_snapshot(
    void *storage,
    const struct sq_tls_token *token,
    struct sq_tls_snapshot *snapshot
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t status;
    if (snapshot == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->abi = SQ_TLS_SNAPSHOT_ABI;
    snapshot->owner_state = owner->state;
    snapshot->policy_attested = owner->policy_attested;
    snapshot->handshake_calls = owner->handshake_calls;
    snapshot->write_calls = owner->write_calls;
    snapshot->read_calls = owner->read_calls;
    snapshot->negotiated_calls = owner->negotiated_calls;
    snapshot->tls_close_actions = owner->tls_close_actions;
    snapshot->raw_close_actions = owner->raw_close_actions;
    snapshot->last_handshake_operation_id =
        owner->handshake_ledger.operation_id;
    snapshot->last_write_operation_id = owner->write_ledger.operation_id;
    snapshot->last_read_operation_id = owner->read_ledger.operation_id;
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_readiness_snapshot(
    void *storage,
    const struct sq_tls_token *token,
    struct sq_tls_readiness_snapshot *snapshot
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t status;
    if (snapshot == NULL) {
        return EINVAL;
    }
    status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->abi = SQ_TLS_READINESS_ABI;
    snapshot->transferred_raw = owner->transferred_raw;
    snapshot->last_direction = owner->last_wait_direction;
    snapshot->wait_calls = owner->wait_calls;
    snapshot->last_max_wait_ns = owner->last_max_wait_ns;
    sq_tls_end_operation(publication, owner);
    return 0;
}

/* Local/offline fault injection: production availability remains false. */
int32_t sq_tls_test_fail_next_write_allocation(
    void *storage,
    const struct sq_tls_token *token
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t status = sq_tls_begin_operation(publication, token, &owner);
    if (status != 0) {
        return status;
    }
    if (owner->state != SQ_OWNER_ACTIVE) {
        sq_tls_end_operation(publication, owner);
        return EPERM;
    }
    owner->fail_next_write_allocation = 1u;
    sq_tls_end_operation(publication, owner);
    return 0;
}

int32_t sq_tls_release(
    void *storage,
    const struct sq_tls_token *token
) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    int32_t status;
    if (publication == NULL || token == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI) {
        return EINVAL;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    if (atomic_load_explicit(
            &publication->state, memory_order_acquire
        ) != SQ_PUBLICATION_PUBLISHED) {
        sq_tls_publication_unlock(publication);
        return ESTALE;
    }
    owner = atomic_load_explicit(&publication->owner, memory_order_relaxed);
    if (owner == NULL || !sq_tls_token_equal(&owner->token, token)) {
        sq_tls_publication_unlock(publication);
        return ESTALE;
    }
    if (publication->pins != 0u ||
        atomic_load_explicit(
            &owner->operation_gate, memory_order_acquire
        ) != 0u ||
        owner->construction_uncertain != 0u ||
        owner->state != SQ_OWNER_CLOSED ||
        owner->raw_close_state != SQ_RESOURCE_CLOSED ||
        owner->tls_close_state != SQ_RESOURCE_CLOSED) {
        sq_tls_publication_unlock(publication);
        return EBUSY;
    }
    memset(&owner->token, 0, sizeof(owner->token));
    atomic_store_explicit(
        &publication->state, SQ_PUBLICATION_RELEASED, memory_order_release
    );
    sq_tls_publication_unlock(publication);
    return 0;
}

int32_t sq_tls_publication_deinit(void *storage) {
    struct sq_tls_publication *publication =
        (struct sq_tls_publication *)storage;
    struct sq_tls_owner *owner;
    uint32_t state;
    int32_t status;
    if (publication == NULL ||
        atomic_load_explicit(
            &publication->abi, memory_order_acquire
        ) != SQ_TLS_PUBLICATION_ABI) {
        return EINVAL;
    }
    status = sq_tls_publication_lock(publication);
    if (status != 0) {
        return status;
    }
    state = atomic_load_explicit(&publication->state, memory_order_acquire);
    owner = atomic_load_explicit(&publication->owner, memory_order_relaxed);
    if (publication->pins != 0u ||
        (state != SQ_PUBLICATION_EMPTY && state != SQ_PUBLICATION_RELEASED) ||
        (state == SQ_PUBLICATION_EMPTY && owner != NULL) ||
        (state == SQ_PUBLICATION_RELEASED && owner == NULL)) {
        sq_tls_publication_unlock(publication);
        return EBUSY;
    }
    if (owner != NULL) {
        if (atomic_load_explicit(
                &owner->operation_gate, memory_order_acquire
            ) != 0u) {
            sq_tls_publication_unlock(publication);
            return EBUSY;
        }
        sq_tls_clear_write_cache(owner);
        memset(owner, 0, sizeof(*owner));
    }
    atomic_store_explicit(&publication->owner, NULL, memory_order_release);
    atomic_store_explicit(&publication->generation, 0u, memory_order_release);
    atomic_store_explicit(
        &publication->state, SQ_PUBLICATION_DEINITIALIZED, memory_order_release
    );
    atomic_store_explicit(&publication->abi, 0u, memory_order_release);
    sq_tls_publication_unlock(publication);
    return 0;
}
