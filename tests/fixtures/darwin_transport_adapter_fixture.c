#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Pure in-memory TLS/adoption table for the native transfer acceptance. */

#define SQ_TLS_VTABLE_ABI 0x53515456u
#define SQ_TLS_VTABLE_VERSION 1u
#define SQ_TLS_ADOPT_VTABLE_ABI 0x53515441u
#define SQ_TLS_ADOPT_VTABLE_VERSION 1u

#define SQ_CALL_COMMITTED 0
#define SQ_CALL_NOT_ISSUED 1
#define SQ_CALL_AMBIGUOUS 2

#define SQ_IO_COMPLETE 1u
#define SQ_IO_WANT_READ 2u
#define SQ_IO_DATA 4u
#define SQ_IO_EOF 5u

#define SQ_MODE_SUCCESS 0
#define SQ_MODE_ADOPT_NOT_ISSUED 1
#define SQ_MODE_ADOPT_AMBIGUOUS_EMPTY 2
#define SQ_MODE_BLOCK_ADOPT 3
#define SQ_MODE_WAIT_AMBIGUOUS 4
#define SQ_MODE_ADOPT_AMBIGUOUS_WITH_TLS 5
#define SQ_MODE_CLOSE_TLS_NOT_ISSUED_ONCE 6
#define SQ_MODE_REENTER_NUMERIC_CLOSE 7
#define SQ_MODE_BLOCK_WRITE 8

#define SQ_FIXTURE_DESCRIPTOR 31337
#define SQ_TLS_HANDLE ((uintptr_t)0x51544151u)

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
typedef int32_t (*sq_fixture_reenter_fn)(void *, void *);

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

struct sq_tls_adopt_vtable {
    uint32_t abi;
    uint32_t size;
    uint32_t version;
    uint32_t reserved;
    sq_tls_adopt_raw_fn adopt_raw;
    sq_tls_wait_ready_fn wait_ready;
};

struct sq_fixture_state {
    _Atomic int32_t mode;
    _Atomic uint32_t create_pair_calls;
    _Atomic uint32_t adopt_calls;
    _Atomic uint32_t handshake_calls;
    _Atomic uint32_t wait_calls;
    _Atomic uint32_t write_calls;
    _Atomic uint32_t read_calls;
    _Atomic uint32_t close_tls_calls;
    _Atomic uint32_t close_raw_vtable_calls;
    _Atomic uint64_t last_wait_ns;
    _Atomic uint32_t last_wait_direction;
    _Atomic uint32_t tls_closed;
    sq_fixture_reenter_fn reenter;
    void *reenter_first;
    void *reenter_second;
    _Atomic int32_t reenter_result;
    pthread_mutex_t block_lock;
    pthread_cond_t block_condition;
    uint32_t adopt_entered;
    uint32_t release_adopt;
    uint32_t write_entered;
    uint32_t release_write;
    _Atomic uint32_t write_saw_original;
};

static struct sq_fixture_state sq_fixture = {
    .block_lock = PTHREAD_MUTEX_INITIALIZER,
    .block_condition = PTHREAD_COND_INITIALIZER,
};

static const uint8_t sq_response[] =
    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

static int32_t sq_fixture_create_pair(
    void *context,
    const uint8_t *hostname,
    size_t hostname_length,
    const uint8_t *alpn,
    size_t alpn_length,
    uintptr_t *raw_output,
    uintptr_t *tls_output
) {
    struct sq_fixture_state *state = context;
    (void)hostname;
    (void)hostname_length;
    (void)alpn;
    (void)alpn_length;
    atomic_fetch_add_explicit(
        &state->create_pair_calls, 1u, memory_order_relaxed
    );
    *raw_output = 0u;
    *tls_output = 0u;
    return SQ_CALL_NOT_ISSUED;
}

static int32_t sq_fixture_adopt_raw(
    void *context,
    int32_t descriptor,
    const uint8_t *hostname,
    size_t hostname_length,
    const uint8_t *alpn,
    size_t alpn_length,
    uintptr_t *tls_output
) {
    struct sq_fixture_state *state = context;
    int32_t mode;
    atomic_fetch_add_explicit(&state->adopt_calls, 1u, memory_order_relaxed);
    if (descriptor != SQ_FIXTURE_DESCRIPTOR || hostname == NULL ||
        hostname_length == 0u || alpn == NULL || alpn_length != 8u ||
        memcmp(alpn, "http/1.1", 8u) != 0) {
        *tls_output = 0u;
        return SQ_CALL_NOT_ISSUED;
    }
    mode = atomic_load_explicit(&state->mode, memory_order_relaxed);
    if (mode == SQ_MODE_ADOPT_NOT_ISSUED) {
        *tls_output = 0u;
        return SQ_CALL_NOT_ISSUED;
    }
    if (mode == SQ_MODE_ADOPT_AMBIGUOUS_EMPTY) {
        *tls_output = 0u;
        return SQ_CALL_AMBIGUOUS;
    }
    if (mode == SQ_MODE_ADOPT_AMBIGUOUS_WITH_TLS) {
        *tls_output = SQ_TLS_HANDLE;
        return SQ_CALL_AMBIGUOUS;
    }
    if (mode == SQ_MODE_REENTER_NUMERIC_CLOSE) {
        if (state->reenter == NULL) {
            *tls_output = 0u;
            return SQ_CALL_AMBIGUOUS;
        }
        atomic_store_explicit(
            &state->reenter_result,
            state->reenter(state->reenter_first, state->reenter_second),
            memory_order_release
        );
    }
    if (mode == SQ_MODE_BLOCK_ADOPT) {
        pthread_mutex_lock(&state->block_lock);
        state->adopt_entered = 1u;
        pthread_cond_broadcast(&state->block_condition);
        while (state->release_adopt == 0u) {
            pthread_cond_wait(&state->block_condition, &state->block_lock);
        }
        pthread_mutex_unlock(&state->block_lock);
    }
    *tls_output = SQ_TLS_HANDLE;
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_wait_ready(
    void *context,
    uintptr_t tls_handle,
    uint32_t direction,
    uint64_t max_wait_ns,
    uint32_t *ready
) {
    struct sq_fixture_state *state = context;
    atomic_fetch_add_explicit(&state->wait_calls, 1u, memory_order_relaxed);
    atomic_store_explicit(
        &state->last_wait_ns, max_wait_ns, memory_order_relaxed
    );
    atomic_store_explicit(
        &state->last_wait_direction, direction, memory_order_relaxed
    );
    *ready = 0u;
    if (tls_handle != SQ_TLS_HANDLE || (direction != 1u && direction != 2u)) {
        return SQ_CALL_AMBIGUOUS;
    }
    if (atomic_load_explicit(&state->mode, memory_order_relaxed) ==
        SQ_MODE_WAIT_AMBIGUOUS) {
        return SQ_CALL_AMBIGUOUS;
    }
    *ready = 1u;
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_handshake(
    void *context,
    uintptr_t tls_handle,
    uint32_t *outcome
) {
    struct sq_fixture_state *state = context;
    uint32_t call_number = atomic_fetch_add_explicit(
        &state->handshake_calls, 1u, memory_order_relaxed
    ) + 1u;
    if (tls_handle != SQ_TLS_HANDLE) {
        return SQ_CALL_AMBIGUOUS;
    }
    *outcome = call_number == 1u ? SQ_IO_WANT_READ : SQ_IO_COMPLETE;
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_write(
    void *context,
    uintptr_t tls_handle,
    const uint8_t *data,
    size_t length,
    uint32_t *outcome,
    size_t *count
) {
    struct sq_fixture_state *state = context;
    atomic_fetch_add_explicit(&state->write_calls, 1u, memory_order_relaxed);
    if (tls_handle != SQ_TLS_HANDLE || data == NULL || length == 0u) {
        return SQ_CALL_AMBIGUOUS;
    }
    if (atomic_load_explicit(&state->mode, memory_order_relaxed) ==
        SQ_MODE_BLOCK_WRITE) {
        pthread_mutex_lock(&state->block_lock);
        state->write_entered = 1u;
        pthread_cond_broadcast(&state->block_condition);
        while (state->release_write == 0u) {
            pthread_cond_wait(&state->block_condition, &state->block_lock);
        }
        pthread_mutex_unlock(&state->block_lock);
        atomic_store_explicit(
            &state->write_saw_original,
            length == 8u && memcmp(data, "original", 8u) == 0 ? 1u : 0u,
            memory_order_release
        );
    }
    *outcome = SQ_IO_COMPLETE;
    *count = length;
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_read(
    void *context,
    uintptr_t tls_handle,
    uint8_t *output,
    size_t maximum,
    uint32_t *outcome,
    size_t *count
) {
    struct sq_fixture_state *state = context;
    uint32_t call_number = atomic_fetch_add_explicit(
        &state->read_calls, 1u, memory_order_relaxed
    ) + 1u;
    if (tls_handle != SQ_TLS_HANDLE || output == NULL) {
        return SQ_CALL_AMBIGUOUS;
    }
    if (call_number == 1u) {
        if (maximum < sizeof(sq_response) - 1u) {
            return SQ_CALL_AMBIGUOUS;
        }
        memcpy(output, sq_response, sizeof(sq_response) - 1u);
        *outcome = SQ_IO_DATA;
        *count = sizeof(sq_response) - 1u;
    } else {
        *outcome = SQ_IO_EOF;
        *count = 0u;
    }
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_negotiated(
    void *context,
    uintptr_t tls_handle,
    uint8_t *alpn_output,
    size_t alpn_capacity,
    size_t *alpn_length,
    uint8_t *version_output,
    size_t version_capacity,
    size_t *version_length
) {
    (void)context;
    if (tls_handle != SQ_TLS_HANDLE || alpn_capacity < 8u ||
        version_capacity < 7u) {
        return SQ_CALL_AMBIGUOUS;
    }
    memcpy(alpn_output, "http/1.1", 8u);
    memcpy(version_output, "TLSv1.3", 7u);
    *alpn_length = 8u;
    *version_length = 7u;
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_close_tls(void *context, uintptr_t tls_handle) {
    struct sq_fixture_state *state = context;
    uint32_t call_number = atomic_fetch_add_explicit(
        &state->close_tls_calls, 1u, memory_order_relaxed
    ) + 1u;
    if (tls_handle != SQ_TLS_HANDLE) {
        return SQ_CALL_AMBIGUOUS;
    }
    if (atomic_load_explicit(&state->mode, memory_order_relaxed) ==
            SQ_MODE_CLOSE_TLS_NOT_ISSUED_ONCE && call_number == 1u) {
        return SQ_CALL_NOT_ISSUED;
    }
    atomic_store_explicit(&state->tls_closed, 1u, memory_order_release);
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_close_raw(void *context, uintptr_t raw_handle) {
    struct sq_fixture_state *state = context;
    (void)raw_handle;
    atomic_fetch_add_explicit(
        &state->close_raw_vtable_calls, 1u, memory_order_relaxed
    );
    return SQ_CALL_AMBIGUOUS;
}

static int32_t sq_fixture_tls_closed(
    void *context,
    uintptr_t tls_handle,
    uint32_t *closed
) {
    struct sq_fixture_state *state = context;
    if (tls_handle != SQ_TLS_HANDLE) {
        return SQ_CALL_AMBIGUOUS;
    }
    *closed = atomic_load_explicit(&state->tls_closed, memory_order_acquire);
    return SQ_CALL_COMMITTED;
}

static int32_t sq_fixture_raw_closed(
    void *context,
    uintptr_t raw_handle,
    uint32_t *closed
) {
    (void)context;
    (void)raw_handle;
    *closed = 0u;
    return SQ_CALL_COMMITTED;
}

static struct sq_tls_vtable sq_tls_vtable = {
    SQ_TLS_VTABLE_ABI,
    sizeof(struct sq_tls_vtable),
    SQ_TLS_VTABLE_VERSION,
    0u,
    sq_fixture_create_pair,
    sq_fixture_handshake,
    sq_fixture_write,
    sq_fixture_read,
    sq_fixture_negotiated,
    sq_fixture_close_tls,
    sq_fixture_close_raw,
    sq_fixture_tls_closed,
    sq_fixture_raw_closed,
};

static struct sq_tls_adopt_vtable sq_adopt_vtable = {
    SQ_TLS_ADOPT_VTABLE_ABI,
    sizeof(struct sq_tls_adopt_vtable),
    SQ_TLS_ADOPT_VTABLE_VERSION,
    0u,
    sq_fixture_adopt_raw,
    sq_fixture_wait_ready,
};

void sq_transport_fixture_reset(int32_t mode) {
    atomic_store_explicit(&sq_fixture.mode, mode, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.create_pair_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.adopt_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.handshake_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.wait_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.write_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.read_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(&sq_fixture.close_tls_calls, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &sq_fixture.close_raw_vtable_calls, 0u, memory_order_relaxed
    );
    atomic_store_explicit(&sq_fixture.last_wait_ns, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &sq_fixture.last_wait_direction, 0u, memory_order_relaxed
    );
    atomic_store_explicit(&sq_fixture.tls_closed, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &sq_fixture.write_saw_original, 0u, memory_order_relaxed
    );
    sq_fixture.reenter = NULL;
    sq_fixture.reenter_first = NULL;
    sq_fixture.reenter_second = NULL;
    atomic_store_explicit(
        &sq_fixture.reenter_result, -1, memory_order_relaxed
    );
    pthread_mutex_lock(&sq_fixture.block_lock);
    sq_fixture.adopt_entered = 0u;
    sq_fixture.release_adopt = 0u;
    sq_fixture.write_entered = 0u;
    sq_fixture.release_write = 0u;
    pthread_mutex_unlock(&sq_fixture.block_lock);
}

const struct sq_tls_vtable *sq_transport_fixture_tls_vtable(void) {
    return &sq_tls_vtable;
}

const struct sq_tls_adopt_vtable *sq_transport_fixture_adopt_vtable(void) {
    return &sq_adopt_vtable;
}

void *sq_transport_fixture_context(void) {
    return &sq_fixture;
}

void sq_transport_fixture_set_reenter_probe(
    sq_fixture_reenter_fn function,
    void *first,
    void *second
) {
    sq_fixture.reenter = function;
    sq_fixture.reenter_first = first;
    sq_fixture.reenter_second = second;
}

int32_t sq_transport_fixture_reenter_result(void) {
    return atomic_load_explicit(
        &sq_fixture.reenter_result, memory_order_acquire
    );
}

uint32_t sq_transport_fixture_adopt_entered(void) {
    uint32_t selected;
    pthread_mutex_lock(&sq_fixture.block_lock);
    selected = sq_fixture.adopt_entered;
    pthread_mutex_unlock(&sq_fixture.block_lock);
    return selected;
}

void sq_transport_fixture_release_adopt(void) {
    pthread_mutex_lock(&sq_fixture.block_lock);
    sq_fixture.release_adopt = 1u;
    pthread_cond_broadcast(&sq_fixture.block_condition);
    pthread_mutex_unlock(&sq_fixture.block_lock);
}

uint32_t sq_transport_fixture_write_entered(void) {
    uint32_t selected;
    pthread_mutex_lock(&sq_fixture.block_lock);
    selected = sq_fixture.write_entered;
    pthread_mutex_unlock(&sq_fixture.block_lock);
    return selected;
}

void sq_transport_fixture_release_write(void) {
    pthread_mutex_lock(&sq_fixture.block_lock);
    sq_fixture.release_write = 1u;
    pthread_cond_broadcast(&sq_fixture.block_condition);
    pthread_mutex_unlock(&sq_fixture.block_lock);
}

uint32_t sq_transport_fixture_write_saw_original(void) {
    return atomic_load_explicit(
        &sq_fixture.write_saw_original, memory_order_acquire
    );
}

#define SQ_COUNTER(name) \
    uint32_t sq_transport_fixture_##name(void) { \
        return atomic_load_explicit( \
            &sq_fixture.name, memory_order_relaxed \
        ); \
    }

SQ_COUNTER(create_pair_calls)
SQ_COUNTER(adopt_calls)
SQ_COUNTER(handshake_calls)
SQ_COUNTER(wait_calls)
SQ_COUNTER(write_calls)
SQ_COUNTER(read_calls)
SQ_COUNTER(close_tls_calls)
SQ_COUNTER(close_raw_vtable_calls)

uint64_t sq_transport_fixture_last_wait_ns(void) {
    return atomic_load_explicit(&sq_fixture.last_wait_ns, memory_order_relaxed);
}

uint32_t sq_transport_fixture_last_wait_direction(void) {
    return atomic_load_explicit(
        &sq_fixture.last_wait_direction, memory_order_relaxed
    );
}
