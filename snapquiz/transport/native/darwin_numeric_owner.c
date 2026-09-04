#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "darwin_owner_transfer.h"

/*
 * Local/offline W09 opaque numeric-socket owner foundation.
 *
 * The descriptor never crosses this ABI.  Callers receive an opaque token,
 * while this registry retains the descriptor, syscall table, one-connect
 * claim, exact packed peer binding, and one-close claim.  Every operation
 * publishes its outcome to caller-owned memory before returning so a language
 * runtime return-event interruption can recover by querying the same token.
 *
 * This file deliberately supplies no production syscall table.  The current
 * Python adapter accepts only an explicitly injected local-test table and the
 * production transport gates remain false.  A later signed bundle must bind a
 * fixed native table and provenance before this code is production eligible.
 */

#define SQ_NUMERIC_ABI 0x53514e31u
#define SQ_NUMERIC_PUBLICATION_MAGIC 0x5351504eu
#define SQ_NUMERIC_OUTCOME_MAGIC 0x53514f4eu
#define SQ_NUMERIC_VTABLE_ABI 0x53515631u
#define SQ_NUMERIC_MAX_OWNERS 64u
#define SQ_NUMERIC_MAX_WAIT_NS 50000000ull

#define SQ_PUBLICATION_NEW 0u
#define SQ_PUBLICATION_IN_FLIGHT 1u
#define SQ_PUBLICATION_COMMITTED 2u

#define SQ_CALL_KNOWN 0
#define SQ_CALL_UNCERTAIN 1

#define SQ_STATUS_OK 0
#define SQ_STATUS_PENDING 1
#define SQ_STATUS_CLOSED 2
#define SQ_STATUS_FAILED 3
#define SQ_STATUS_UNCERTAIN 4
#define SQ_STATUS_INVALID_TOKEN 5
#define SQ_STATUS_INVALID_STATE 6
#define SQ_STATUS_BUSY 7
#define SQ_STATUS_INVALID_ARGUMENT 8
#define SQ_STATUS_CAPACITY 9

#define SQ_ERROR_NONE 0
#define SQ_ERROR_CREATE 1
#define SQ_ERROR_CONNECT 2
#define SQ_ERROR_POLL 3
#define SQ_ERROR_SOCKET_ERROR 4
#define SQ_ERROR_PEER 5
#define SQ_ERROR_CLOSE 6
#define SQ_ERROR_TOKEN 7
#define SQ_ERROR_ARGUMENT 8
#define SQ_ERROR_CAPACITY 9
#define SQ_ERROR_TRANSFER 10

#define SQ_OWNER_EMPTY 0
#define SQ_OWNER_CREATE_IN_FLIGHT 1
#define SQ_OWNER_CREATED 2
#define SQ_OWNER_CONNECT_IN_FLIGHT 3
#define SQ_OWNER_PENDING 4
#define SQ_OWNER_POLL_IN_FLIGHT 5
#define SQ_OWNER_VERIFY_IN_FLIGHT 6
#define SQ_OWNER_CONNECTED 7
#define SQ_OWNER_FAILED 8
#define SQ_OWNER_CONNECT_UNCERTAIN 9
#define SQ_OWNER_POLL_UNCERTAIN 10
#define SQ_OWNER_VERIFY_UNCERTAIN 11
#define SQ_OWNER_CLOSE_IN_FLIGHT 12
#define SQ_OWNER_CLOSED 13
#define SQ_OWNER_CLOSE_UNCERTAIN 14
#define SQ_OWNER_CREATE_UNCERTAIN 15
#define SQ_OWNER_TRANSFER_IN_FLIGHT 16
#define SQ_OWNER_TRANSFERRED 17
#define SQ_OWNER_TRANSFER_UNCERTAIN 18

struct sq_numeric_create_publication {
    uint32_t abi;
    _Atomic uint32_t publication_state;
    int32_t status;
    int32_t owner_state;
    uint8_t token[32];
    uint32_t magic;
    uint32_t reserved;
};

struct sq_numeric_outcome {
    uint32_t abi;
    _Atomic uint32_t publication_state;
    int32_t status;
    int32_t owner_state;
    int32_t error_code;
    uint32_t connect_count;
    uint32_t close_count;
    uint32_t peer_exact;
    uint32_t family;
    uint32_t nonblocking;
    uint32_t magic;
};

typedef int32_t (*sq_socket_create_fn)(
    void *context,
    int32_t family,
    int32_t socket_type,
    int32_t protocol,
    int32_t *descriptor,
    int32_t *error_number
);
typedef int32_t (*sq_connect_once_fn)(
    void *context,
    int32_t descriptor,
    const struct sockaddr *address,
    uint32_t address_length,
    int32_t *result,
    int32_t *error_number
);
typedef int32_t (*sq_set_nonblocking_fn)(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *error_number
);
typedef int32_t (*sq_poll_writable_fn)(
    void *context,
    int32_t descriptor,
    uint64_t max_wait_ns,
    int32_t *result,
    int32_t *error_number
);
typedef int32_t (*sq_socket_error_fn)(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *socket_error,
    int32_t *error_number
);
typedef int32_t (*sq_peername_fn)(
    void *context,
    int32_t descriptor,
    struct sockaddr_storage *address,
    uint32_t *address_length,
    int32_t *result,
    int32_t *error_number
);
typedef int32_t (*sq_close_once_fn)(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *error_number
);

struct sq_numeric_syscalls {
    uint32_t abi;
    uint32_t size;
    void *context;
    sq_socket_create_fn socket_create;
    sq_set_nonblocking_fn set_nonblocking;
    sq_connect_once_fn connect_once;
    sq_poll_writable_fn poll_writable;
    sq_socket_error_fn socket_error;
    sq_peername_fn peername;
    sq_close_once_fn close_once;
};

struct sq_numeric_token {
    uint8_t bytes[32];
};

struct sq_numeric_owner_slot {
    struct sq_numeric_token token;
    uint32_t generation;
    int32_t state;
    int32_t descriptor;
    int32_t family;
    uint8_t expected_address[16];
    uint32_t expected_address_length;
    uint16_t expected_port;
    uint16_t reserved;
    uint32_t connect_count;
    uint32_t close_count;
    uint32_t peer_exact;
    uint32_t nonblocking;
    int32_t error_code;
    struct sq_numeric_syscalls syscalls;
};

static pthread_mutex_t sq_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sq_numeric_owner_slot sq_owners[SQ_NUMERIC_MAX_OWNERS];

#if ATOMIC_INT_LOCK_FREE != 2
#error "numeric owner requires lock-free 32-bit atomics"
#endif

_Static_assert(
    sizeof(_Atomic uint32_t) == sizeof(uint32_t),
    "atomic publication width mismatch"
);
_Static_assert(
    offsetof(struct sq_numeric_create_publication, token) == 16,
    "create token offset mismatch"
);
_Static_assert(
    sizeof(struct sq_numeric_create_publication) == 56,
    "create publication size mismatch"
);
_Static_assert(
    sizeof(struct sq_numeric_outcome) == 44,
    "operation outcome size mismatch"
);

static int sq_token_is_zero(const struct sq_numeric_token *token) {
    uint8_t combined = 0;
    size_t index;
    if (token == NULL) {
        return 1;
    }
    for (index = 0; index < sizeof(token->bytes); ++index) {
        combined |= token->bytes[index];
    }
    return combined == 0;
}

static int sq_token_equal(
    const struct sq_numeric_token *left,
    const struct sq_numeric_token *right
) {
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < sizeof(left->bytes); ++index) {
        difference |= left->bytes[index] ^ right->bytes[index];
    }
    return difference == 0;
}

static void sq_new_token(struct sq_numeric_token *token) {
    uint32_t index;
    int collision;
    do {
        arc4random_buf(token->bytes, sizeof(token->bytes));
        collision = 0;
        for (index = 0; index < SQ_NUMERIC_MAX_OWNERS; ++index) {
            if (sq_owners[index].state != SQ_OWNER_EMPTY &&
                sq_token_equal(&sq_owners[index].token, token)) {
                collision = 1;
            }
        }
    } while (sq_token_is_zero(token) || collision);
}

static int sq_vtable_valid(const struct sq_numeric_syscalls *syscalls) {
    return syscalls != NULL && syscalls->abi == SQ_NUMERIC_VTABLE_ABI &&
        syscalls->size == sizeof(struct sq_numeric_syscalls) &&
        syscalls->socket_create != NULL &&
        syscalls->set_nonblocking != NULL && syscalls->connect_once != NULL &&
        syscalls->poll_writable != NULL && syscalls->socket_error != NULL &&
        syscalls->peername != NULL && syscalls->close_once != NULL;
}

static int sq_pending_error(int32_t error_number) {
    return error_number == EINPROGRESS || error_number == EALREADY ||
        error_number == EINTR || error_number == EWOULDBLOCK;
}

static void sq_begin_create_publication(
    struct sq_numeric_create_publication *publication
) {
    publication->status = SQ_STATUS_FAILED;
    publication->owner_state = SQ_OWNER_EMPTY;
    memset(publication->token, 0, sizeof(publication->token));
    publication->magic = 0;
    publication->reserved = 0;
    atomic_store_explicit(
        &publication->publication_state,
        SQ_PUBLICATION_IN_FLIGHT,
        memory_order_release
    );
}

static void sq_commit_create_publication(
    struct sq_numeric_create_publication *publication,
    int32_t status,
    int32_t owner_state,
    const struct sq_numeric_token *token
) {
    publication->status = status;
    publication->owner_state = owner_state;
    if (token == NULL) {
        memset(publication->token, 0, sizeof(publication->token));
    } else {
        memcpy(publication->token, token->bytes, sizeof(publication->token));
    }
    publication->magic = SQ_NUMERIC_PUBLICATION_MAGIC;
    atomic_store_explicit(
        &publication->publication_state,
        SQ_PUBLICATION_COMMITTED,
        memory_order_release
    );
}

static void sq_begin_outcome(struct sq_numeric_outcome *outcome) {
    outcome->status = SQ_STATUS_FAILED;
    outcome->owner_state = SQ_OWNER_EMPTY;
    outcome->error_code = SQ_ERROR_NONE;
    outcome->connect_count = 0;
    outcome->close_count = 0;
    outcome->peer_exact = 0;
    outcome->family = 0;
    outcome->nonblocking = 0;
    outcome->magic = 0;
    atomic_store_explicit(
        &outcome->publication_state,
        SQ_PUBLICATION_IN_FLIGHT,
        memory_order_release
    );
}

static void sq_commit_outcome_values(
    struct sq_numeric_outcome *outcome,
    int32_t status,
    int32_t owner_state,
    int32_t error_code,
    uint32_t connect_count,
    uint32_t close_count,
    uint32_t peer_exact,
    uint32_t family,
    uint32_t nonblocking
) {
    outcome->status = status;
    outcome->owner_state = owner_state;
    outcome->error_code = error_code;
    outcome->connect_count = connect_count;
    outcome->close_count = close_count;
    outcome->peer_exact = peer_exact;
    outcome->family = family;
    outcome->nonblocking = nonblocking;
    outcome->magic = SQ_NUMERIC_OUTCOME_MAGIC;
    atomic_store_explicit(
        &outcome->publication_state,
        SQ_PUBLICATION_COMMITTED,
        memory_order_release
    );
}

static void sq_commit_outcome_slot(
    struct sq_numeric_outcome *outcome,
    const struct sq_numeric_owner_slot *slot,
    int32_t status
) {
    sq_commit_outcome_values(
        outcome,
        status,
        slot->state,
        slot->error_code,
        slot->connect_count,
        slot->close_count,
        slot->peer_exact,
        (uint32_t)slot->family,
        slot->nonblocking
    );
}

static struct sq_numeric_owner_slot *sq_find_owner(
    const struct sq_numeric_token *token
) {
    uint32_t index;
    if (token == NULL || sq_token_is_zero(token)) {
        return NULL;
    }
    for (index = 0; index < SQ_NUMERIC_MAX_OWNERS; ++index) {
        if (sq_owners[index].state != SQ_OWNER_EMPTY &&
            sq_token_equal(&sq_owners[index].token, token)) {
            return &sq_owners[index];
        }
    }
    return NULL;
}

static int32_t sq_status_for_state(int32_t state) {
    switch (state) {
        case SQ_OWNER_CREATED:
        case SQ_OWNER_CONNECTED:
            return SQ_STATUS_OK;
        case SQ_OWNER_PENDING:
            return SQ_STATUS_PENDING;
        case SQ_OWNER_CLOSED:
        case SQ_OWNER_TRANSFERRED:
            return SQ_STATUS_CLOSED;
        case SQ_OWNER_CONNECT_UNCERTAIN:
        case SQ_OWNER_POLL_UNCERTAIN:
        case SQ_OWNER_VERIFY_UNCERTAIN:
        case SQ_OWNER_CLOSE_UNCERTAIN:
        case SQ_OWNER_CREATE_UNCERTAIN:
        case SQ_OWNER_TRANSFER_UNCERTAIN:
            return SQ_STATUS_UNCERTAIN;
        case SQ_OWNER_CREATE_IN_FLIGHT:
        case SQ_OWNER_CONNECT_IN_FLIGHT:
        case SQ_OWNER_POLL_IN_FLIGHT:
        case SQ_OWNER_VERIFY_IN_FLIGHT:
        case SQ_OWNER_CLOSE_IN_FLIGHT:
        case SQ_OWNER_TRANSFER_IN_FLIGHT:
            return SQ_STATUS_BUSY;
        default:
            return SQ_STATUS_FAILED;
    }
}

static int sq_peer_matches(
    const struct sq_numeric_owner_slot *slot,
    const struct sockaddr_storage *storage,
    uint32_t address_length
) {
    if (slot->family == AF_INET) {
        const struct sockaddr_in *peer;
        if (address_length != sizeof(struct sockaddr_in)) {
            return 0;
        }
        peer = (const struct sockaddr_in *)(const void *)storage;
        return peer->sin_family == AF_INET &&
#ifdef __APPLE__
            peer->sin_len == sizeof(*peer) &&
#endif
            peer->sin_port == htons(slot->expected_port) &&
            memcmp(
                &peer->sin_addr,
                slot->expected_address,
                sizeof(peer->sin_addr)
            ) == 0;
    }
    if (slot->family == AF_INET6) {
        const struct sockaddr_in6 *peer;
        if (address_length != sizeof(struct sockaddr_in6)) {
            return 0;
        }
        peer = (const struct sockaddr_in6 *)(const void *)storage;
        return peer->sin6_family == AF_INET6 &&
#ifdef __APPLE__
            peer->sin6_len == sizeof(*peer) &&
#endif
            peer->sin6_port == htons(slot->expected_port) &&
            peer->sin6_flowinfo == 0 && peer->sin6_scope_id == 0 &&
            memcmp(
                &peer->sin6_addr,
                slot->expected_address,
                sizeof(peer->sin6_addr)
            ) == 0;
    }
    return 0;
}

static int32_t sq_verify_connected(
    struct sq_numeric_owner_slot *slot,
    const struct sq_numeric_token *token,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_syscalls syscalls = slot->syscalls;
    int32_t descriptor = slot->descriptor;
    int32_t certainty;
    int32_t result = -1;
    int32_t socket_error = -1;
    int32_t error_number = 0;
    struct sockaddr_storage peer;
    uint32_t peer_length = (uint32_t)sizeof(peer);
    int exact = 0;

    memset(&peer, 0, sizeof(peer));
    certainty = syscalls.socket_error(
        syscalls.context,
        descriptor,
        &result,
        &socket_error,
        &error_number
    );
    if (certainty == SQ_CALL_KNOWN && result == 0 && socket_error == 0) {
        result = -1;
        error_number = 0;
        certainty = syscalls.peername(
            syscalls.context,
            descriptor,
            &peer,
            &peer_length,
            &result,
            &error_number
        );
        if (certainty == SQ_CALL_KNOWN && result == 0) {
            exact = sq_peer_matches(slot, &peer, peer_length);
        }
    } else if (certainty == SQ_CALL_KNOWN) {
        exact = -1;
    }

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL || slot->state != SQ_OWNER_VERIFY_IN_FLIGHT) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (certainty != SQ_CALL_KNOWN) {
        slot->state = SQ_OWNER_VERIFY_UNCERTAIN;
        slot->error_code = SQ_ERROR_PEER;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
    } else if (exact != 1) {
        slot->state = SQ_OWNER_FAILED;
        slot->error_code = exact == -1 ? SQ_ERROR_SOCKET_ERROR : SQ_ERROR_PEER;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_FAILED);
    } else {
        slot->state = SQ_OWNER_CONNECTED;
        slot->error_code = SQ_ERROR_NONE;
        slot->peer_exact = 1;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_OK);
    }
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}

uint32_t sq_numeric_owner_abi(void) {
    return SQ_NUMERIC_ABI;
}

uint32_t sq_numeric_syscalls_size(void) {
    return (uint32_t)sizeof(struct sq_numeric_syscalls);
}

uint32_t sq_numeric_transfer_contract_abi(void) {
    return SQ_OWNER_TRANSFER_CONTRACT_ABI;
}

uint32_t sq_numeric_transfer_contract_size(void) {
    return (uint32_t)sizeof(struct sq_owner_transfer_contract_descriptor);
}

uint32_t sq_numeric_transfer_contract_version(void) {
    return SQ_OWNER_TRANSFER_CONTRACT_VERSION;
}

int32_t sq_numeric_owner_create_publish(
    struct sq_numeric_create_publication *publication,
    int32_t family,
    int32_t socket_type,
    int32_t protocol,
    const struct sq_numeric_syscalls *syscalls
) {
    struct sq_numeric_owner_slot *slot = NULL;
    uint32_t index;
    int32_t certainty;
    int32_t nonblocking_certainty = SQ_CALL_UNCERTAIN;
    int32_t descriptor = -1;
    int32_t nonblocking_result = -1;
    int32_t error_number = 0;
    struct sq_numeric_token token;

    if (publication == NULL || publication->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &publication->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_create_publication(publication);
    if ((family != AF_INET && family != AF_INET6) ||
        socket_type != SOCK_STREAM || protocol != IPPROTO_TCP ||
        !sq_vtable_valid(syscalls)) {
        sq_commit_create_publication(
            publication,
            SQ_STATUS_INVALID_ARGUMENT,
            SQ_OWNER_EMPTY,
            NULL
        );
        return 0;
    }

    pthread_mutex_lock(&sq_registry_lock);
    for (index = 0; index < SQ_NUMERIC_MAX_OWNERS; ++index) {
        if (sq_owners[index].state == SQ_OWNER_EMPTY) {
            slot = &sq_owners[index];
            break;
        }
    }
    if (slot == NULL) {
        pthread_mutex_unlock(&sq_registry_lock);
        sq_commit_create_publication(
            publication,
            SQ_STATUS_CAPACITY,
            SQ_OWNER_EMPTY,
            NULL
        );
        return 0;
    }
    slot->generation += 1u;
    if (slot->generation == 0) {
        slot->generation = 1u;
    }
    sq_new_token(&token);
    memset(slot->expected_address, 0, sizeof(slot->expected_address));
    memcpy(&slot->token, &token, sizeof(token));
    slot->state = SQ_OWNER_CREATE_IN_FLIGHT;
    slot->descriptor = -1;
    slot->family = family;
    slot->expected_address_length = 0;
    slot->expected_port = 0;
    slot->reserved = 0;
    slot->connect_count = 0;
    slot->close_count = 0;
    slot->peer_exact = 0;
    slot->nonblocking = 0;
    slot->error_code = SQ_ERROR_NONE;
    slot->syscalls = *syscalls;
    pthread_mutex_unlock(&sq_registry_lock);

    certainty = syscalls->socket_create(
        syscalls->context,
        family,
        socket_type,
        protocol,
        &descriptor,
        &error_number
    );
    if (certainty == SQ_CALL_KNOWN && descriptor >= 0) {
        error_number = 0;
        nonblocking_certainty = syscalls->set_nonblocking(
            syscalls->context,
            descriptor,
            &nonblocking_result,
            &error_number
        );
    }

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(&token);
    if (slot == NULL || slot->state != SQ_OWNER_CREATE_IN_FLIGHT) {
        pthread_mutex_unlock(&sq_registry_lock);
        sq_commit_create_publication(
            publication,
            SQ_STATUS_UNCERTAIN,
            SQ_OWNER_EMPTY,
            NULL
        );
        return 0;
    }
    if (certainty != SQ_CALL_KNOWN) {
        slot->descriptor = descriptor;
        slot->state = SQ_OWNER_CREATE_UNCERTAIN;
        slot->error_code = SQ_ERROR_CREATE;
        sq_commit_create_publication(
            publication,
            SQ_STATUS_UNCERTAIN,
            slot->state,
            &token
        );
    } else if (descriptor < 0) {
        uint32_t generation = slot->generation;
        memset(slot, 0, sizeof(*slot));
        slot->generation = generation;
        sq_commit_create_publication(
            publication,
            SQ_STATUS_FAILED,
            SQ_OWNER_EMPTY,
            NULL
        );
    } else if (nonblocking_certainty != SQ_CALL_KNOWN ||
               nonblocking_result != 0) {
        slot->descriptor = descriptor;
        slot->state = SQ_OWNER_CREATE_UNCERTAIN;
        slot->error_code = SQ_ERROR_CREATE;
        sq_commit_create_publication(
            publication,
            SQ_STATUS_UNCERTAIN,
            slot->state,
            &token
        );
    } else {
        slot->descriptor = descriptor;
        slot->nonblocking = 1u;
        slot->state = SQ_OWNER_CREATED;
        sq_commit_create_publication(
            publication,
            SQ_STATUS_OK,
            slot->state,
            &token
        );
    }
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}

int32_t sq_numeric_owner_connect_publish(
    const struct sq_numeric_token *token,
    int32_t family,
    const uint8_t *packed_address,
    uint32_t packed_address_length,
    uint16_t port,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_owner_slot *slot;
    struct sq_numeric_syscalls syscalls;
    struct sockaddr_storage target;
    uint32_t target_length;
    int32_t descriptor;
    int32_t certainty;
    int32_t result = -1;
    int32_t error_number = 0;

    if (outcome == NULL || outcome->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &outcome->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_outcome(outcome);
    if (sq_token_is_zero(token) || packed_address == NULL || port == 0 ||
        ((family == AF_INET && packed_address_length != 4) ||
         (family == AF_INET6 && packed_address_length != 16)) ||
        (family != AF_INET && family != AF_INET6)) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_ARGUMENT,
            SQ_OWNER_EMPTY,
            SQ_ERROR_ARGUMENT,
            0,
            0,
            0,
            0,
            0
        );
        return 0;
    }

    memset(&target, 0, sizeof(target));
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)(void *)&target;
#ifdef __APPLE__
        address->sin_len = sizeof(*address);
#endif
        address->sin_family = AF_INET;
        address->sin_port = htons(port);
        memcpy(&address->sin_addr, packed_address, 4);
        target_length = (uint32_t)sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)(void *)&target;
#ifdef __APPLE__
        address->sin6_len = sizeof(*address);
#endif
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(port);
        address->sin6_flowinfo = 0;
        memcpy(&address->sin6_addr, packed_address, 16);
        address->sin6_scope_id = 0;
        target_length = (uint32_t)sizeof(*address);
    }

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state != SQ_OWNER_CREATED || slot->family != family) {
        sq_commit_outcome_slot(
            outcome,
            slot,
            sq_status_for_state(slot->state) == SQ_STATUS_BUSY
                ? SQ_STATUS_BUSY
                : SQ_STATUS_INVALID_STATE
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    memcpy(slot->expected_address, packed_address, packed_address_length);
    slot->expected_address_length = packed_address_length;
    slot->expected_port = port;
    slot->connect_count = 1;
    slot->peer_exact = 0;
    slot->error_code = SQ_ERROR_NONE;
    slot->state = SQ_OWNER_CONNECT_IN_FLIGHT;
    syscalls = slot->syscalls;
    descriptor = slot->descriptor;
    pthread_mutex_unlock(&sq_registry_lock);

    certainty = syscalls.connect_once(
        syscalls.context,
        descriptor,
        (const struct sockaddr *)(const void *)&target,
        target_length,
        &result,
        &error_number
    );

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL || slot->state != SQ_OWNER_CONNECT_IN_FLIGHT) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (certainty != SQ_CALL_KNOWN || (result != 0 && result != -1)) {
        slot->state = SQ_OWNER_CONNECT_UNCERTAIN;
        slot->error_code = SQ_ERROR_CONNECT;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (result == -1 && sq_pending_error(error_number)) {
        slot->state = SQ_OWNER_PENDING;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_PENDING);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (result == -1) {
        slot->state = SQ_OWNER_FAILED;
        slot->error_code = SQ_ERROR_CONNECT;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_FAILED);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    slot->state = SQ_OWNER_VERIFY_IN_FLIGHT;
    pthread_mutex_unlock(&sq_registry_lock);
    return sq_verify_connected(slot, token, outcome);
}

int32_t sq_numeric_owner_poll_publish(
    const struct sq_numeric_token *token,
    uint64_t max_wait_ns,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_owner_slot *slot;
    struct sq_numeric_syscalls syscalls;
    int32_t descriptor;
    int32_t certainty;
    int32_t result = -1;
    int32_t error_number = 0;

    if (outcome == NULL || outcome->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &outcome->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_outcome(outcome);
    if (sq_token_is_zero(token) || max_wait_ns == 0 ||
        max_wait_ns > SQ_NUMERIC_MAX_WAIT_NS) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_ARGUMENT,
            SQ_OWNER_EMPTY,
            SQ_ERROR_ARGUMENT,
            0,
            0,
            0,
            0,
            0
        );
        return 0;
    }

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_CONNECTED) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_OK);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state != SQ_OWNER_PENDING) {
        sq_commit_outcome_slot(
            outcome,
            slot,
            sq_status_for_state(slot->state) == SQ_STATUS_BUSY
                ? SQ_STATUS_BUSY
                : SQ_STATUS_INVALID_STATE
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    slot->state = SQ_OWNER_POLL_IN_FLIGHT;
    syscalls = slot->syscalls;
    descriptor = slot->descriptor;
    pthread_mutex_unlock(&sq_registry_lock);

    certainty = syscalls.poll_writable(
        syscalls.context,
        descriptor,
        max_wait_ns,
        &result,
        &error_number
    );

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL || slot->state != SQ_OWNER_POLL_IN_FLIGHT) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (certainty != SQ_CALL_KNOWN ||
        (result != -1 && result != 0 && result != 1)) {
        slot->state = SQ_OWNER_POLL_UNCERTAIN;
        slot->error_code = SQ_ERROR_POLL;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (result == 0) {
        slot->state = SQ_OWNER_PENDING;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_PENDING);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (result == -1) {
        slot->state = SQ_OWNER_FAILED;
        slot->error_code = SQ_ERROR_POLL;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_FAILED);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    slot->state = SQ_OWNER_VERIFY_IN_FLIGHT;
    pthread_mutex_unlock(&sq_registry_lock);
    return sq_verify_connected(slot, token, outcome);
}

int32_t sq_numeric_owner_query_publish(
    const struct sq_numeric_token *token,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_owner_slot *slot;
    if (outcome == NULL || outcome->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &outcome->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_outcome(outcome);
    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
    } else {
        sq_commit_outcome_slot(outcome, slot, sq_status_for_state(slot->state));
    }
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}

int32_t sq_numeric_owner_transfer_publish(
    const struct sq_numeric_token *token,
    sq_numeric_transfer_accept_fn accept,
    void *accept_context,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_owner_slot *slot;
    sq_transferred_raw_close_fn raw_close;
    void *raw_close_context;
    int32_t descriptor;
    int32_t family;
    uint32_t connect_count;
    uint32_t peer_exact;
    int32_t accepted;

    if (outcome == NULL || outcome->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &outcome->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_outcome(outcome);
    if (sq_token_is_zero(token) || accept == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_ARGUMENT,
            SQ_OWNER_EMPTY,
            SQ_ERROR_ARGUMENT,
            0,
            0,
            0,
            0,
            0
        );
        return 0;
    }

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state != SQ_OWNER_CONNECTED || slot->descriptor < 0 ||
        slot->connect_count != 1u || slot->peer_exact != 1u ||
        slot->nonblocking != 1u || slot->close_count != 0u) {
        sq_commit_outcome_slot(
            outcome,
            slot,
            sq_status_for_state(slot->state) == SQ_STATUS_BUSY
                ? SQ_STATUS_BUSY
                : SQ_STATUS_INVALID_STATE
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    slot->state = SQ_OWNER_TRANSFER_IN_FLIGHT;
    descriptor = slot->descriptor;
    family = slot->family;
    raw_close_context = slot->syscalls.context;
    raw_close = slot->syscalls.close_once;
    connect_count = slot->connect_count;
    peer_exact = slot->peer_exact;
    pthread_mutex_unlock(&sq_registry_lock);

    accepted = accept(
        accept_context,
        descriptor,
        family,
        raw_close_context,
        raw_close,
        connect_count,
        peer_exact
    );

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL || slot->state != SQ_OWNER_TRANSFER_IN_FLIGHT) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_UNCERTAIN,
            SQ_OWNER_TRANSFER_UNCERTAIN,
            SQ_ERROR_TRANSFER,
            connect_count,
            0,
            peer_exact,
            (uint32_t)family,
            1
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (accepted == SQ_TRANSFER_NOT_ISSUED) {
        slot->state = SQ_OWNER_CONNECTED;
        slot->error_code = SQ_ERROR_TRANSFER;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_FAILED);
    } else if (accepted == SQ_TRANSFER_COMMITTED_OWNED) {
        slot->descriptor = -1;
        slot->state = SQ_OWNER_TRANSFERRED;
        slot->error_code = SQ_ERROR_NONE;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_OK);
    } else {
        /*
         * A malformed/ambiguous accept result is never followed by a source
         * close: the destination may already own the descriptor.  Keep a
         * permanent source tombstone and make the destination publication the
         * sole recovery authority.
         */
        slot->descriptor = -1;
        slot->state = SQ_OWNER_TRANSFER_UNCERTAIN;
        slot->error_code = SQ_ERROR_TRANSFER;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
    }
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}

int32_t sq_numeric_owner_close_publish(
    const struct sq_numeric_token *token,
    struct sq_numeric_outcome *outcome
) {
    struct sq_numeric_owner_slot *slot;
    struct sq_numeric_syscalls syscalls;
    int32_t descriptor;
    int32_t certainty;
    int32_t result = -1;
    int32_t error_number = 0;

    if (outcome == NULL || outcome->abi != SQ_NUMERIC_ABI ||
        atomic_load_explicit(
            &outcome->publication_state,
            memory_order_acquire
        ) != SQ_PUBLICATION_NEW) {
        return EINVAL;
    }
    sq_begin_outcome(outcome);
    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_CLOSED) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_CLOSED);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_TRANSFERRED) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_CLOSED);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_TRANSFER_UNCERTAIN) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_CLOSE_UNCERTAIN) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->state == SQ_OWNER_CREATE_IN_FLIGHT ||
        slot->state == SQ_OWNER_CONNECT_IN_FLIGHT ||
        slot->state == SQ_OWNER_POLL_IN_FLIGHT ||
        slot->state == SQ_OWNER_VERIFY_IN_FLIGHT ||
        slot->state == SQ_OWNER_CLOSE_IN_FLIGHT ||
        slot->state == SQ_OWNER_TRANSFER_IN_FLIGHT) {
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_BUSY);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    if (slot->descriptor < 0) {
        slot->state = SQ_OWNER_CLOSE_UNCERTAIN;
        slot->error_code = SQ_ERROR_CLOSE;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    slot->state = SQ_OWNER_CLOSE_IN_FLIGHT;
    slot->close_count += 1u;
    syscalls = slot->syscalls;
    descriptor = slot->descriptor;
    pthread_mutex_unlock(&sq_registry_lock);

    certainty = syscalls.close_once(
        syscalls.context,
        descriptor,
        &result,
        &error_number
    );

    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL || slot->state != SQ_OWNER_CLOSE_IN_FLIGHT) {
        sq_commit_outcome_values(
            outcome,
            SQ_STATUS_INVALID_TOKEN,
            SQ_OWNER_EMPTY,
            SQ_ERROR_TOKEN,
            0,
            0,
            0,
            0,
            0
        );
        pthread_mutex_unlock(&sq_registry_lock);
        return 0;
    }
    /* Never repeat close after the native action boundary, even on EINTR. */
    slot->descriptor = -1;
    if (certainty == SQ_CALL_KNOWN && result == 0) {
        slot->state = SQ_OWNER_CLOSED;
        slot->error_code = SQ_ERROR_NONE;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_CLOSED);
    } else {
        slot->state = SQ_OWNER_CLOSE_UNCERTAIN;
        slot->error_code = SQ_ERROR_CLOSE;
        sq_commit_outcome_slot(outcome, slot, SQ_STATUS_UNCERTAIN);
    }
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}

int32_t sq_numeric_owner_retire(const struct sq_numeric_token *token) {
    struct sq_numeric_owner_slot *slot;
    uint32_t generation;
    if (token == NULL || sq_token_is_zero(token)) {
        return EINVAL;
    }
    pthread_mutex_lock(&sq_registry_lock);
    slot = sq_find_owner(token);
    if (slot == NULL) {
        pthread_mutex_unlock(&sq_registry_lock);
        return ENOENT;
    }
    if (!((slot->state == SQ_OWNER_CLOSED && slot->close_count == 1u) ||
          ((slot->state == SQ_OWNER_TRANSFERRED ||
            slot->state == SQ_OWNER_TRANSFER_UNCERTAIN) &&
           slot->close_count == 0u)) ||
        slot->descriptor != -1) {
        pthread_mutex_unlock(&sq_registry_lock);
        return EBUSY;
    }
    generation = slot->generation;
    memset(slot, 0, sizeof(*slot));
    slot->generation = generation;
    pthread_mutex_unlock(&sq_registry_lock);
    return 0;
}
