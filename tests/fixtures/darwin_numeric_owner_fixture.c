#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

/* Pure in-memory syscall table for darwin_numeric_owner.c acceptance tests. */

#define SQ_NUMERIC_VTABLE_ABI 0x53515631u
#define SQ_CALL_KNOWN 0
#define SQ_CALL_UNCERTAIN 1
#define SQ_FIXTURE_DESCRIPTOR 31337

#define SQ_MODE_IMMEDIATE 0
#define SQ_MODE_PENDING_THEN_READY 1
#define SQ_MODE_CONNECT_UNCERTAIN 2
#define SQ_MODE_CLOSE_UNCERTAIN 3
#define SQ_MODE_PEER_MISMATCH 4
#define SQ_MODE_SOCKET_ERROR 5
#define SQ_MODE_POLL_UNCERTAIN 6
#define SQ_MODE_CREATE_FAILED 7
#define SQ_MODE_CREATE_UNCERTAIN 8
#define SQ_MODE_CLOSE_FAILED 9

typedef int32_t (*sq_socket_create_fn)(
    void *, int32_t, int32_t, int32_t, int32_t *, int32_t *
);
typedef int32_t (*sq_connect_once_fn)(
    void *, int32_t, const struct sockaddr *, uint32_t, int32_t *, int32_t *
);
typedef int32_t (*sq_set_nonblocking_fn)(
    void *, int32_t, int32_t *, int32_t *
);
typedef int32_t (*sq_poll_writable_fn)(
    void *, int32_t, uint64_t, int32_t *, int32_t *
);
typedef int32_t (*sq_socket_error_fn)(
    void *, int32_t, int32_t *, int32_t *, int32_t *
);
typedef int32_t (*sq_peername_fn)(
    void *, int32_t, struct sockaddr_storage *, uint32_t *, int32_t *, int32_t *
);
typedef int32_t (*sq_close_once_fn)(
    void *, int32_t, int32_t *, int32_t *
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

struct sq_fixture_state {
    _Atomic int32_t mode;
    _Atomic uint32_t create_calls;
    _Atomic uint32_t set_nonblocking_calls;
    _Atomic uint32_t connect_calls;
    _Atomic uint32_t poll_calls;
    _Atomic uint32_t socket_error_calls;
    _Atomic uint32_t peername_calls;
    _Atomic uint32_t close_calls;
    _Atomic uint64_t last_wait_ns;
    struct sockaddr_storage target;
    uint32_t target_length;
};

static struct sq_fixture_state sq_fixture;

static int32_t sq_fixture_socket_create(
    void *context,
    int32_t family,
    int32_t socket_type,
    int32_t protocol,
    int32_t *descriptor,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    int32_t mode;
    (void)family;
    (void)socket_type;
    (void)protocol;
    atomic_fetch_add_explicit(&state->create_calls, 1u, memory_order_relaxed);
    mode = atomic_load_explicit(&state->mode, memory_order_relaxed);
    if (mode == SQ_MODE_CREATE_FAILED) {
        *descriptor = -1;
        *error_number = EMFILE;
        return SQ_CALL_KNOWN;
    }
    *descriptor = SQ_FIXTURE_DESCRIPTOR;
    *error_number = 0;
    return mode == SQ_MODE_CREATE_UNCERTAIN
        ? SQ_CALL_UNCERTAIN
        : SQ_CALL_KNOWN;
}

static int32_t sq_fixture_connect_once(
    void *context,
    int32_t descriptor,
    const struct sockaddr *address,
    uint32_t address_length,
    int32_t *result,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    int32_t mode;
    atomic_fetch_add_explicit(&state->connect_calls, 1u, memory_order_relaxed);
    if (descriptor != SQ_FIXTURE_DESCRIPTOR || address == NULL ||
        address_length > sizeof(state->target)) {
        *result = -1;
        *error_number = EBADF;
        return SQ_CALL_UNCERTAIN;
    }
    memset(&state->target, 0, sizeof(state->target));
    memcpy(&state->target, address, address_length);
    state->target_length = address_length;
    mode = atomic_load_explicit(&state->mode, memory_order_relaxed);
    if (mode == SQ_MODE_CONNECT_UNCERTAIN) {
        *result = -1;
        *error_number = EINPROGRESS;
        return SQ_CALL_UNCERTAIN;
    }
    if (mode == SQ_MODE_PENDING_THEN_READY ||
        mode == SQ_MODE_POLL_UNCERTAIN) {
        *result = -1;
        *error_number = EINPROGRESS;
        return SQ_CALL_KNOWN;
    }
    *result = 0;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static int32_t sq_fixture_set_nonblocking(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    atomic_fetch_add_explicit(
        &state->set_nonblocking_calls,
        1u,
        memory_order_relaxed
    );
    if (descriptor != SQ_FIXTURE_DESCRIPTOR) {
        *result = -1;
        *error_number = EBADF;
        return SQ_CALL_KNOWN;
    }
    *result = 0;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static int32_t sq_fixture_poll_writable(
    void *context,
    int32_t descriptor,
    uint64_t max_wait_ns,
    int32_t *result,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    uint32_t call_number;
    int32_t mode;
    call_number = atomic_fetch_add_explicit(
        &state->poll_calls,
        1u,
        memory_order_relaxed
    ) + 1u;
    atomic_store_explicit(
        &state->last_wait_ns,
        max_wait_ns,
        memory_order_relaxed
    );
    if (descriptor != SQ_FIXTURE_DESCRIPTOR) {
        *result = -1;
        *error_number = EBADF;
        return SQ_CALL_UNCERTAIN;
    }
    mode = atomic_load_explicit(&state->mode, memory_order_relaxed);
    if (mode == SQ_MODE_POLL_UNCERTAIN) {
        *result = -1;
        *error_number = EINTR;
        return SQ_CALL_UNCERTAIN;
    }
    *result = call_number == 1u ? 0 : 1;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static int32_t sq_fixture_socket_error(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *socket_error,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    atomic_fetch_add_explicit(
        &state->socket_error_calls,
        1u,
        memory_order_relaxed
    );
    if (descriptor != SQ_FIXTURE_DESCRIPTOR) {
        *result = -1;
        *socket_error = 0;
        *error_number = EBADF;
        return SQ_CALL_KNOWN;
    }
    *result = 0;
    *socket_error = atomic_load_explicit(
        &state->mode,
        memory_order_relaxed
    ) == SQ_MODE_SOCKET_ERROR ? ECONNREFUSED : 0;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static int32_t sq_fixture_peername(
    void *context,
    int32_t descriptor,
    struct sockaddr_storage *address,
    uint32_t *address_length,
    int32_t *result,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    atomic_fetch_add_explicit(
        &state->peername_calls,
        1u,
        memory_order_relaxed
    );
    if (descriptor != SQ_FIXTURE_DESCRIPTOR || address == NULL ||
        address_length == NULL || *address_length < state->target_length) {
        *result = -1;
        *error_number = EBADF;
        return SQ_CALL_KNOWN;
    }
    memcpy(address, &state->target, state->target_length);
    *address_length = state->target_length;
    if (atomic_load_explicit(&state->mode, memory_order_relaxed) ==
        SQ_MODE_PEER_MISMATCH) {
        if (address->ss_family == AF_INET) {
            struct sockaddr_in *peer = (struct sockaddr_in *)(void *)address;
            peer->sin_port ^= htons(1u);
        } else if (address->ss_family == AF_INET6) {
            struct sockaddr_in6 *peer = (struct sockaddr_in6 *)(void *)address;
            peer->sin6_port ^= htons(1u);
        }
    }
    *result = 0;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static int32_t sq_fixture_close_once(
    void *context,
    int32_t descriptor,
    int32_t *result,
    int32_t *error_number
) {
    struct sq_fixture_state *state = context;
    int32_t mode;
    atomic_fetch_add_explicit(&state->close_calls, 1u, memory_order_relaxed);
    mode = atomic_load_explicit(&state->mode, memory_order_relaxed);
    if (descriptor != SQ_FIXTURE_DESCRIPTOR) {
        *result = -1;
        *error_number = EBADF;
        return SQ_CALL_UNCERTAIN;
    }
    if (mode == SQ_MODE_CLOSE_UNCERTAIN) {
        *result = -1;
        *error_number = EINTR;
        return SQ_CALL_UNCERTAIN;
    }
    if (mode == SQ_MODE_CLOSE_FAILED) {
        *result = -1;
        *error_number = EINTR;
        return SQ_CALL_KNOWN;
    }
    *result = 0;
    *error_number = 0;
    return SQ_CALL_KNOWN;
}

static struct sq_numeric_syscalls sq_fixture_vtable = {
    SQ_NUMERIC_VTABLE_ABI,
    sizeof(struct sq_numeric_syscalls),
    &sq_fixture,
    sq_fixture_socket_create,
    sq_fixture_set_nonblocking,
    sq_fixture_connect_once,
    sq_fixture_poll_writable,
    sq_fixture_socket_error,
    sq_fixture_peername,
    sq_fixture_close_once,
};

void sq_numeric_fixture_reset(int32_t mode) {
    memset(&sq_fixture.target, 0, sizeof(sq_fixture.target));
    sq_fixture.target_length = 0;
    atomic_store_explicit(&sq_fixture.mode, mode, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.create_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &sq_fixture.set_nonblocking_calls,
        0u,
        memory_order_relaxed
    );
    atomic_store_explicit(&sq_fixture.connect_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.poll_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &sq_fixture.socket_error_calls,
        0u,
        memory_order_relaxed
    );
    atomic_store_explicit(&sq_fixture.peername_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.close_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.last_wait_ns, 0u, memory_order_relaxed);
}

const struct sq_numeric_syscalls *sq_numeric_fixture_vtable(void) {
    return &sq_fixture_vtable;
}

uint32_t sq_numeric_fixture_create_calls(void) {
    return atomic_load_explicit(&sq_fixture.create_calls, memory_order_relaxed);
}

uint32_t sq_numeric_fixture_connect_calls(void) {
    return atomic_load_explicit(&sq_fixture.connect_calls, memory_order_relaxed);
}

uint32_t sq_numeric_fixture_set_nonblocking_calls(void) {
    return atomic_load_explicit(
        &sq_fixture.set_nonblocking_calls,
        memory_order_relaxed
    );
}

uint32_t sq_numeric_fixture_poll_calls(void) {
    return atomic_load_explicit(&sq_fixture.poll_calls, memory_order_relaxed);
}

uint32_t sq_numeric_fixture_socket_error_calls(void) {
    return atomic_load_explicit(
        &sq_fixture.socket_error_calls,
        memory_order_relaxed
    );
}

uint32_t sq_numeric_fixture_peername_calls(void) {
    return atomic_load_explicit(&sq_fixture.peername_calls, memory_order_relaxed);
}

uint32_t sq_numeric_fixture_close_calls(void) {
    return atomic_load_explicit(&sq_fixture.close_calls, memory_order_relaxed);
}

uint64_t sq_numeric_fixture_last_wait_ns(void) {
    return atomic_load_explicit(&sq_fixture.last_wait_ns, memory_order_relaxed);
}
