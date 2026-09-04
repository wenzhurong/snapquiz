#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/*
 * Unwired W09 resolver-owner foundation.
 *
 * The caller prepares and retains this storage before process creation.  The
 * injected create callback publishes directly into that storage, so losing
 * the callback return cannot lose an exact PID/descriptor outcome.  Every
 * effectful lane has its own terminal uncertainty ledger: an uncertain action
 * is never replayed, while untouched cleanup lanes remain available.
 *
 * There is deliberately no production selection, resolver implementation,
 * credential access, DNS, socket creation, process creation, or signing here.
 */

#define SQ_RESOLVER_OWNER_ABI 0x53515234u
#define SQ_RESOLVER_OWNER_VTABLE_ABI 0x53515632u
#define SQ_RESOLVER_OWNER_MAGIC 0x53514f57u
#define SQ_RESOLVER_CALLBACK_MAGIC 0x53514342u
#define SQ_RESOLVER_OUTPUT_VIEW_MAGIC 0x53514f56u
#define SQ_RESOLVER_SNAPSHOT_MAGIC 0x5351534eu

#define SQ_RESOLVER_FD_COUNT 4u
#define SQ_RESOLVER_OUTPUT_COUNT 3u
#define SQ_RESOLVER_DIGEST_BYTES 32u
#define SQ_RESOLVER_MAX_CONTROL_BYTES 4096u
#define SQ_RESOLVER_MAX_OUTPUT_BYTES 16385u
#define SQ_RESOLVER_MAX_WAIT_NS UINT64_C(50000000)

#define SQ_OWNER_OK 0
#define SQ_OWNER_PENDING 1
#define SQ_OWNER_FAILED 2
#define SQ_OWNER_UNCERTAIN 3
#define SQ_OWNER_INVALID 4
#define SQ_OWNER_BUSY 5

#define SQ_CALLBACK_RETURNED 0

#define SQ_ACTION_COMPLETE 1u
#define SQ_ACTION_PENDING 2u

#define SQ_OUTPUT_READY 1u
#define SQ_OUTPUT_RESULT 2u
#define SQ_OUTPUT_EOF 3u

#define SQ_STATE_NEW 0u
#define SQ_STATE_CONSTRUCTING 1u
#define SQ_STATE_CHILD_OWNED 2u
#define SQ_STATE_RECOVERY_OWNED 3u
#define SQ_STATE_CREATE_FAILED 4u
#define SQ_STATE_CREATE_UNCERTAIN 5u

#define SQ_PUBLICATION_NONE 0u
#define SQ_PUBLICATION_CREATED 1u
#define SQ_PUBLICATION_FAILED 2u
#define SQ_PUBLICATION_INVALID 3u
#define SQ_PUBLICATION_WRITING 4u

#define SQ_CREATE_BOUNDARY_NONE 0u
#define SQ_CREATE_BOUNDARY_RETURNED 1u
#define SQ_CREATE_BOUNDARY_AMBIGUOUS 2u

#define SQ_UNCERTAINTY_NONE 0u
#define SQ_UNCERTAINTY_CREATE_RETURN 1u
#define SQ_UNCERTAINTY_CREATE_PUBLICATION 2u

#define SQ_LANE_IDLE 0u
#define SQ_LANE_IN_FLIGHT 1u
#define SQ_LANE_DONE 2u
#define SQ_LANE_UNCERTAIN 3u
#define SQ_LANE_FAILED 4u

struct sq_resolver_action_result {
    uint32_t magic;
    uint32_t outcome;
    int32_t error_code;
    int32_t value;
    uint32_t byte_count;
};

typedef int32_t (*sq_resolver_create_fn)(
    void *context,
    void *owner_storage,
    uint64_t max_wait_ns
);
typedef int32_t (*sq_resolver_signal_fn)(
    void *context,
    int32_t pid,
    int32_t signal_number,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);
typedef int32_t (*sq_resolver_wait_fn)(
    void *context,
    int32_t pid,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);
typedef int32_t (*sq_resolver_close_fn)(
    void *context,
    int32_t fd,
    uint32_t role,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);
typedef int32_t (*sq_resolver_control_fn)(
    void *context,
    int32_t fd,
    const uint8_t *bytes,
    uint32_t byte_count,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);
typedef int32_t (*sq_resolver_output_fn)(
    void *context,
    int32_t fd,
    uint32_t sequence,
    uint8_t *bytes,
    uint32_t capacity,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);
typedef int32_t (*sq_resolver_liveness_fn)(
    void *context,
    int32_t fd,
    uint64_t max_wait_ns,
    struct sq_resolver_action_result *result
);

struct sq_resolver_owner_vtable {
    uint32_t abi;
    uint32_t size;
    sq_resolver_create_fn create_process;
    sq_resolver_signal_fn signal_process;
    sq_resolver_wait_fn wait_process;
    sq_resolver_close_fn close_fd;
    sq_resolver_control_fn write_control;
    sq_resolver_output_fn read_output;
    sq_resolver_liveness_fn check_liveness;
};

struct sq_resolver_output_view {
    uint32_t magic;
    uint32_t sequence;
    uint32_t kind;
    uint32_t byte_count;
};

struct sq_resolver_owner_snapshot {
    uint32_t magic;
    uint32_t state;
    uint32_t publication;
    uint32_t uncertainty_reason;
    int32_t pid;
    int32_t fds[SQ_RESOLVER_FD_COUNT];
    uint32_t closed_mask;
    uint32_t signal_state;
    uint32_t wait_state;
    int32_t wait_status;
    uint32_t close_states[SQ_RESOLVER_FD_COUNT];
    uint32_t control_state;
    uint32_t next_output_sequence;
    uint32_t output_state;
    uint32_t output_slot_present;
    uint32_t output_slot_kind;
    uint32_t output_slot_bytes;
    uint32_t output_acked_mask;
    uint32_t liveness_state;
    int32_t liveness_value;
};

struct sq_resolver_owner {
    uint32_t abi;
    uint32_t size;
    uint32_t magic;
    _Atomic uint32_t operation_gate;
    _Atomic uint32_t state;
    _Atomic uint32_t publication;
    _Atomic int32_t published_pid;
    _Atomic int32_t published_fds[SQ_RESOLVER_FD_COUNT];
    _Atomic int32_t published_error;
    uint32_t uncertainty_reason;
    _Atomic uint32_t create_boundary;
    struct sq_resolver_owner_vtable calls;
    void *context;
    int32_t create_error;
    int32_t pid;
    int32_t fds[SQ_RESOLVER_FD_COUNT];
    uint32_t signal_state;
    int32_t signal_number;
    uint32_t wait_state;
    int32_t wait_status;
    uint32_t close_states[SQ_RESOLVER_FD_COUNT];
    uint32_t closed_mask;
    uint32_t control_state;
    uint32_t control_byte_count;
    uint8_t control_bytes[SQ_RESOLVER_MAX_CONTROL_BYTES];
    uint32_t output_state;
    uint32_t output_slot_present;
    uint32_t output_sequence;
    uint32_t output_kind;
    uint32_t output_byte_count;
    uint8_t output_bytes[SQ_RESOLVER_MAX_OUTPUT_BYTES];
    uint32_t output_acked_mask;
    uint32_t acked_kinds[SQ_RESOLVER_OUTPUT_COUNT];
    uint32_t acked_byte_counts[SQ_RESOLVER_OUTPUT_COUNT];
    uint64_t acked_fingerprints[SQ_RESOLVER_OUTPUT_COUNT];
    uint8_t acked_digests[SQ_RESOLVER_OUTPUT_COUNT][SQ_RESOLVER_DIGEST_BYTES];
    uint32_t liveness_state;
    int32_t liveness_value;
};

#if ATOMIC_INT_LOCK_FREE != 2
#error "resolver owner requires lock-free 32-bit atomics"
#endif

_Static_assert(sizeof(int32_t) == 4u, "int32_t width mismatch");
_Static_assert(sizeof(uint32_t) == 4u, "uint32_t width mismatch");

static int owner_valid(const struct sq_resolver_owner *owner) {
    return owner != NULL && owner->abi == SQ_RESOLVER_OWNER_ABI &&
        owner->size == sizeof(*owner) && owner->magic == SQ_RESOLVER_OWNER_MAGIC;
}

static int vtable_valid(const struct sq_resolver_owner_vtable *calls) {
    return calls != NULL && calls->abi == SQ_RESOLVER_OWNER_VTABLE_ABI &&
        calls->size == sizeof(*calls) && calls->create_process != NULL &&
        calls->signal_process != NULL && calls->wait_process != NULL &&
        calls->close_fd != NULL && calls->write_control != NULL &&
        calls->read_output != NULL && calls->check_liveness != NULL;
}

static int wait_valid(uint64_t max_wait_ns) {
    return max_wait_ns > 0u && max_wait_ns <= SQ_RESOLVER_MAX_WAIT_NS;
}

static int enter_owner(struct sq_resolver_owner *owner) {
    uint32_t expected = 0u;

    return atomic_compare_exchange_strong_explicit(
        &owner->operation_gate,
        &expected,
        1u,
        memory_order_acq_rel,
        memory_order_acquire
    ) ? SQ_OWNER_OK : SQ_OWNER_BUSY;
}

static int leave_owner(struct sq_resolver_owner *owner, int status) {
    atomic_store_explicit(&owner->operation_gate, 0u, memory_order_release);
    return status;
}

static int resource_values_valid(
    int32_t pid,
    const int32_t fds[SQ_RESOLVER_FD_COUNT]
) {
    uint32_t left;
    uint32_t right;

    if (pid <= 0) {
        return 0;
    }
    for (left = 0u; left < SQ_RESOLVER_FD_COUNT; left += 1u) {
        if (fds[left] < 3) {
            return 0;
        }
        for (right = left + 1u; right < SQ_RESOLVER_FD_COUNT; right += 1u) {
            if (fds[left] == fds[right]) {
                return 0;
            }
        }
    }
    return 1;
}

static int exact_resources_valid_locked(
    const struct sq_resolver_owner *owner
) {
    return resource_values_valid(owner->pid, owner->fds);
}

static int cleanup_state_locked(const struct sq_resolver_owner *owner) {
    uint32_t state = atomic_load_explicit(&owner->state, memory_order_acquire);
    uint32_t publication = atomic_load_explicit(
        &owner->publication,
        memory_order_acquire
    );

    if ((state == SQ_STATE_CHILD_OWNED ||
         state == SQ_STATE_RECOVERY_OWNED) &&
        publication == SQ_PUBLICATION_CREATED &&
        exact_resources_valid_locked(owner)) {
        return SQ_OWNER_OK;
    }
    if (state == SQ_STATE_CREATE_UNCERTAIN ||
        state == SQ_STATE_RECOVERY_OWNED) {
        return SQ_OWNER_UNCERTAIN;
    }
    return SQ_OWNER_FAILED;
}

static int normal_state_locked(const struct sq_resolver_owner *owner) {
    return atomic_load_explicit(&owner->state, memory_order_acquire) ==
        SQ_STATE_CHILD_OWNED && atomic_load_explicit(
            &owner->publication,
            memory_order_acquire) == SQ_PUBLICATION_CREATED &&
        exact_resources_valid_locked(owner) ? SQ_OWNER_OK : SQ_OWNER_FAILED;
}

static int action_result_shape_valid(
    const struct sq_resolver_action_result *result
) {
    return result->magic == SQ_RESOLVER_CALLBACK_MAGIC &&
        (result->outcome == SQ_ACTION_COMPLETE ||
         result->outcome == SQ_ACTION_PENDING) && result->error_code >= 0;
}

static int terminal_lane_status(uint32_t lane) {
    if (lane == SQ_LANE_UNCERTAIN) {
        return SQ_OWNER_UNCERTAIN;
    }
    if (lane == SQ_LANE_FAILED) {
        return SQ_OWNER_FAILED;
    }
    if (lane == SQ_LANE_IN_FLIGHT) {
        return SQ_OWNER_BUSY;
    }
    return SQ_OWNER_OK;
}

static uint64_t bytes_fingerprint(const uint8_t *bytes, uint32_t byte_count) {
    uint64_t selected = UINT64_C(1469598103934665603);
    uint32_t index;

    for (index = 0u; index < byte_count; index += 1u) {
        selected ^= (uint64_t)bytes[index];
        selected *= UINT64_C(1099511628211);
    }
    selected ^= (uint64_t)byte_count;
    selected *= UINT64_C(1099511628211);
    return selected;
}

static uint32_t expected_output_kind(uint32_t sequence) {
    if (sequence == 0u) {
        return SQ_OUTPUT_READY;
    }
    if (sequence == 1u) {
        return SQ_OUTPUT_RESULT;
    }
    if (sequence == 2u) {
        return SQ_OUTPUT_EOF;
    }
    return 0u;
}

static int output_payload_valid(
    uint32_t sequence,
    uint32_t kind,
    const uint8_t *bytes,
    uint32_t byte_count
) {
    static const uint8_t ready[] = "SNAPQUIZ-RESOLVER/2 READY\n";

    if (kind != expected_output_kind(sequence) ||
        byte_count > SQ_RESOLVER_MAX_OUTPUT_BYTES) {
        return 0;
    }
    if (kind == SQ_OUTPUT_READY) {
        return byte_count == sizeof(ready) - 1u &&
            memcmp(bytes, ready, sizeof(ready) - 1u) == 0;
    }
    if (kind == SQ_OUTPUT_RESULT) {
        return byte_count > 0u && bytes[byte_count - 1u] == (uint8_t)'\n' &&
            !(byte_count == sizeof(ready) - 1u &&
              memcmp(bytes, ready, sizeof(ready) - 1u) == 0);
    }
    return byte_count == 0u;
}

size_t sq_resolver_owner_size(void) {
    return sizeof(struct sq_resolver_owner);
}

uint32_t sq_resolver_owner_abi(void) {
    return SQ_RESOLVER_OWNER_ABI;
}

uint32_t sq_resolver_owner_vtable_abi(void) {
    return SQ_RESOLVER_OWNER_VTABLE_ABI;
}

uint32_t sq_resolver_owner_max_control_bytes(void) {
    return SQ_RESOLVER_MAX_CONTROL_BYTES;
}

uint32_t sq_resolver_owner_max_output_bytes(void) {
    return SQ_RESOLVER_MAX_OUTPUT_BYTES;
}

uint64_t sq_resolver_owner_max_wait_ns(void) {
    return SQ_RESOLVER_MAX_WAIT_NS;
}

int32_t sq_resolver_owner_prepare(void *storage, size_t byte_count) {
    struct sq_resolver_owner *owner;
    uint32_t index;

    if (storage == NULL || byte_count < sizeof(struct sq_resolver_owner)) {
        return SQ_OWNER_INVALID;
    }
    memset(storage, 0, sizeof(struct sq_resolver_owner));
    owner = (struct sq_resolver_owner *)storage;
    owner->abi = SQ_RESOLVER_OWNER_ABI;
    owner->size = (uint32_t)sizeof(*owner);
    owner->magic = SQ_RESOLVER_OWNER_MAGIC;
    atomic_init(&owner->state, SQ_STATE_NEW);
    atomic_init(&owner->publication, SQ_PUBLICATION_NONE);
    atomic_init(&owner->published_pid, 0);
    atomic_init(&owner->published_error, 0);
    owner->pid = 0;
    owner->wait_status = -1;
    owner->liveness_value = -1;
    for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
        owner->fds[index] = -1;
        atomic_init(&owner->published_fds[index], -1);
        owner->close_states[index] = SQ_LANE_IDLE;
    }
    atomic_init(&owner->operation_gate, 0u);
    atomic_init(&owner->create_boundary, SQ_CREATE_BOUNDARY_NONE);
    return SQ_OWNER_OK;
}

int32_t sq_resolver_owner_publish_created(
    void *storage,
    int32_t pid,
    const int32_t fds[SQ_RESOLVER_FD_COUNT]
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint32_t expected = SQ_PUBLICATION_NONE;
    uint32_t index;
    int valid;

    if (!owner_valid(owner) || fds == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (atomic_load_explicit(&owner->state, memory_order_acquire) !=
        SQ_STATE_CONSTRUCTING) {
        return SQ_OWNER_FAILED;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &owner->publication,
            &expected,
            SQ_PUBLICATION_WRITING,
            memory_order_acq_rel,
            memory_order_acquire)) {
        return SQ_OWNER_FAILED;
    }
    atomic_store_explicit(&owner->published_pid, pid, memory_order_relaxed);
    for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
        atomic_store_explicit(
            &owner->published_fds[index],
            fds[index],
            memory_order_relaxed
        );
    }
    valid = resource_values_valid(pid, fds);
    atomic_store_explicit(
        &owner->publication,
        valid ? SQ_PUBLICATION_CREATED : SQ_PUBLICATION_INVALID,
        memory_order_release
    );
    return valid ? SQ_OWNER_OK : SQ_OWNER_UNCERTAIN;
}

int32_t sq_resolver_owner_publish_create_failed(
    void *storage,
    int32_t error_code
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint32_t expected = SQ_PUBLICATION_NONE;

    if (!owner_valid(owner)) {
        return SQ_OWNER_INVALID;
    }
    if (atomic_load_explicit(&owner->state, memory_order_acquire) !=
        SQ_STATE_CONSTRUCTING) {
        return SQ_OWNER_FAILED;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &owner->publication,
            &expected,
            SQ_PUBLICATION_WRITING,
            memory_order_acq_rel,
            memory_order_acquire)) {
        return SQ_OWNER_FAILED;
    }
    atomic_store_explicit(
        &owner->published_error,
        error_code,
        memory_order_relaxed
    );
    atomic_store_explicit(
        &owner->publication,
        error_code > 0 ? SQ_PUBLICATION_FAILED : SQ_PUBLICATION_INVALID,
        memory_order_release
    );
    return error_code > 0 ? SQ_OWNER_OK : SQ_OWNER_UNCERTAIN;
}

static int finalize_construct_locked(struct sq_resolver_owner *owner) {
    uint32_t boundary = atomic_load_explicit(
        &owner->create_boundary,
        memory_order_acquire
    );
    uint32_t publication = atomic_load_explicit(
        &owner->publication,
        memory_order_acquire
    );
    int32_t published_fds[SQ_RESOLVER_FD_COUNT];
    int32_t published_pid;
    uint32_t index;

    if (boundary == SQ_CREATE_BOUNDARY_NONE) {
        return SQ_OWNER_BUSY;
    }
    if (publication == SQ_PUBLICATION_WRITING) {
        return SQ_OWNER_BUSY;
    }
    published_pid = atomic_load_explicit(
        &owner->published_pid,
        memory_order_relaxed
    );
    for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
        published_fds[index] = atomic_load_explicit(
            &owner->published_fds[index],
            memory_order_relaxed
        );
    }
    if (publication == SQ_PUBLICATION_CREATED &&
        resource_values_valid(published_pid, published_fds)) {
        owner->pid = published_pid;
        for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
            owner->fds[index] = published_fds[index];
        }
        if (boundary == SQ_CREATE_BOUNDARY_RETURNED) {
            atomic_store_explicit(
                &owner->state,
                SQ_STATE_CHILD_OWNED,
                memory_order_release
            );
            return SQ_OWNER_OK;
        }
        atomic_store_explicit(
            &owner->state,
            SQ_STATE_RECOVERY_OWNED,
            memory_order_release
        );
        owner->uncertainty_reason = SQ_UNCERTAINTY_CREATE_RETURN;
        return SQ_OWNER_UNCERTAIN;
    }
    owner->create_error = atomic_load_explicit(
        &owner->published_error,
        memory_order_relaxed
    );
    if (publication == SQ_PUBLICATION_FAILED && owner->create_error > 0) {
        atomic_store_explicit(
            &owner->state,
            SQ_STATE_CREATE_FAILED,
            memory_order_release
        );
        return SQ_OWNER_FAILED;
    }
    atomic_store_explicit(
        &owner->state,
        SQ_STATE_CREATE_UNCERTAIN,
        memory_order_release
    );
    if (owner->uncertainty_reason == SQ_UNCERTAINTY_NONE) {
        owner->uncertainty_reason = SQ_UNCERTAINTY_CREATE_PUBLICATION;
    }
    return SQ_OWNER_UNCERTAIN;
}

int32_t sq_resolver_owner_construct(
    void *storage,
    const struct sq_resolver_owner_vtable *calls,
    void *context,
    uint64_t max_wait_ns
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    sq_resolver_create_fn create_process;
    int32_t boundary;
    int status;
    uint32_t state;

    if (!owner_valid(owner) || !vtable_valid(calls) ||
        !wait_valid(max_wait_ns)) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    state = atomic_load_explicit(&owner->state, memory_order_acquire);
    if (state == SQ_STATE_CHILD_OWNED) {
        return leave_owner(owner, SQ_OWNER_OK);
    }
    if (state == SQ_STATE_RECOVERY_OWNED ||
        state == SQ_STATE_CREATE_UNCERTAIN) {
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (state == SQ_STATE_CREATE_FAILED) {
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (state == SQ_STATE_CONSTRUCTING) {
        status = finalize_construct_locked(owner);
        return leave_owner(owner, status);
    }
    if (state != SQ_STATE_NEW) {
        return leave_owner(owner, SQ_OWNER_INVALID);
    }
    owner->calls = *calls;
    owner->context = context;
    atomic_store_explicit(
        &owner->state,
        SQ_STATE_CONSTRUCTING,
        memory_order_release
    );
    atomic_store_explicit(
        &owner->create_boundary,
        SQ_CREATE_BOUNDARY_NONE,
        memory_order_release
    );
    create_process = owner->calls.create_process;
    (void)leave_owner(owner, SQ_OWNER_OK);

    boundary = create_process(context, storage, max_wait_ns);
    atomic_store_explicit(
        &owner->create_boundary,
        boundary == SQ_CALLBACK_RETURNED ?
            SQ_CREATE_BOUNDARY_RETURNED : SQ_CREATE_BOUNDARY_AMBIGUOUS,
        memory_order_release
    );
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = finalize_construct_locked(owner);
    return leave_owner(owner, status);
}

int32_t sq_resolver_owner_signal(
    void *storage,
    int32_t pid,
    int32_t signal_number,
    uint64_t max_wait_ns
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result = {0u, 0u, 0, 0, 0u};
    int32_t boundary;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns) || pid <= 0 ||
        signal_number <= 0) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = cleanup_state_locked(owner);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    if (pid != owner->pid) {
        return leave_owner(owner, SQ_OWNER_INVALID);
    }
    if (owner->signal_state == SQ_LANE_DONE) {
        status = owner->signal_number == signal_number ?
            SQ_OWNER_OK : SQ_OWNER_INVALID;
        return leave_owner(owner, status);
    }
    status = terminal_lane_status(owner->signal_state);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    if (owner->wait_state == SQ_LANE_DONE ||
        owner->wait_state == SQ_LANE_UNCERTAIN) {
        return leave_owner(
            owner,
            owner->wait_state == SQ_LANE_UNCERTAIN ?
                SQ_OWNER_UNCERTAIN : SQ_OWNER_FAILED
        );
    }
    owner->signal_state = SQ_LANE_IN_FLIGHT;
    boundary = owner->calls.signal_process(
        owner->context,
        owner->pid,
        signal_number,
        max_wait_ns,
        &result
    );
    if (boundary != SQ_CALLBACK_RETURNED ||
        !action_result_shape_valid(&result) ||
        result.outcome != SQ_ACTION_COMPLETE || result.value != 0 ||
        result.byte_count != 0u) {
        owner->signal_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.error_code != 0) {
        owner->signal_state = SQ_LANE_FAILED;
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    owner->signal_number = signal_number;
    owner->signal_state = SQ_LANE_DONE;
    return leave_owner(owner, SQ_OWNER_OK);
}

int32_t sq_resolver_owner_wait(
    void *storage,
    int32_t pid,
    uint64_t max_wait_ns,
    int32_t *wait_status
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result = {0u, 0u, 0, 0, 0u};
    int32_t boundary;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns) || pid <= 0 ||
        wait_status == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = cleanup_state_locked(owner);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    if (pid != owner->pid) {
        return leave_owner(owner, SQ_OWNER_INVALID);
    }
    if (owner->wait_state == SQ_LANE_DONE) {
        *wait_status = owner->wait_status;
        return leave_owner(owner, SQ_OWNER_OK);
    }
    status = terminal_lane_status(owner->wait_state);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    owner->wait_state = SQ_LANE_IN_FLIGHT;
    boundary = owner->calls.wait_process(
        owner->context,
        owner->pid,
        max_wait_ns,
        &result
    );
    if (boundary != SQ_CALLBACK_RETURNED ||
        !action_result_shape_valid(&result) || result.byte_count != 0u) {
        owner->wait_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.outcome == SQ_ACTION_PENDING) {
        if (result.error_code != 0 || result.value != 0) {
            owner->wait_state = SQ_LANE_UNCERTAIN;
            return leave_owner(owner, SQ_OWNER_UNCERTAIN);
        }
        owner->wait_state = SQ_LANE_IDLE;
        return leave_owner(owner, SQ_OWNER_PENDING);
    }
    if (result.error_code != 0) {
        owner->wait_state = SQ_LANE_FAILED;
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (result.value < 0) {
        owner->wait_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    owner->wait_status = result.value;
    owner->wait_state = SQ_LANE_DONE;
    *wait_status = owner->wait_status;
    return leave_owner(owner, SQ_OWNER_OK);
}

/*
 * Opaque-owner cleanup entry points.
 *
 * The composition layer intentionally does not materialize the real child
 * PID in Python.  These wrappers select the already-published identity inside
 * native storage and then enter the same exact-once action ledgers as the
 * explicit-PID ABI.  The selected PID is immutable after construction, while
 * the called function still performs the authoritative state/gate checks.
 */
int32_t sq_resolver_owner_signal_owned(
    void *storage,
    int32_t signal_number,
    uint64_t max_wait_ns
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint32_t publication;
    uint32_t state;

    if (!owner_valid(owner)) {
        return SQ_OWNER_INVALID;
    }
    state = atomic_load_explicit(&owner->state, memory_order_acquire);
    publication = atomic_load_explicit(
        &owner->publication,
        memory_order_acquire
    );
    if ((state != SQ_STATE_CHILD_OWNED &&
         state != SQ_STATE_RECOVERY_OWNED) ||
        publication != SQ_PUBLICATION_CREATED) {
        return state == SQ_STATE_CREATE_UNCERTAIN ?
            SQ_OWNER_UNCERTAIN : SQ_OWNER_FAILED;
    }
    return sq_resolver_owner_signal(
        storage,
        owner->pid,
        signal_number,
        max_wait_ns
    );
}

int32_t sq_resolver_owner_wait_owned(
    void *storage,
    uint64_t max_wait_ns,
    int32_t *wait_status
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint32_t publication;
    uint32_t state;

    if (!owner_valid(owner)) {
        return SQ_OWNER_INVALID;
    }
    state = atomic_load_explicit(&owner->state, memory_order_acquire);
    publication = atomic_load_explicit(
        &owner->publication,
        memory_order_acquire
    );
    if ((state != SQ_STATE_CHILD_OWNED &&
         state != SQ_STATE_RECOVERY_OWNED) ||
        publication != SQ_PUBLICATION_CREATED) {
        return state == SQ_STATE_CREATE_UNCERTAIN ?
            SQ_OWNER_UNCERTAIN : SQ_OWNER_FAILED;
    }
    return sq_resolver_owner_wait(
        storage,
        owner->pid,
        max_wait_ns,
        wait_status
    );
}

int32_t sq_resolver_owner_close(void *storage, uint64_t max_wait_ns) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result;
    uint32_t index;
    int32_t boundary;
    int overall = SQ_OWNER_OK;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns)) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = cleanup_state_locked(owner);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
        if (owner->close_states[index] == SQ_LANE_DONE) {
            continue;
        }
        if (owner->close_states[index] == SQ_LANE_UNCERTAIN) {
            overall = SQ_OWNER_UNCERTAIN;
            continue;
        }
        if (owner->close_states[index] == SQ_LANE_FAILED) {
            if (overall == SQ_OWNER_OK) {
                overall = SQ_OWNER_FAILED;
            }
            continue;
        }
        if (owner->close_states[index] == SQ_LANE_IN_FLIGHT) {
            if (overall == SQ_OWNER_OK) {
                overall = SQ_OWNER_BUSY;
            }
            continue;
        }
        memset(&result, 0, sizeof(result));
        owner->close_states[index] = SQ_LANE_IN_FLIGHT;
        boundary = owner->calls.close_fd(
            owner->context,
            owner->fds[index],
            index,
            max_wait_ns,
            &result
        );
        if (boundary != SQ_CALLBACK_RETURNED ||
            !action_result_shape_valid(&result) ||
            result.outcome != SQ_ACTION_COMPLETE || result.value != 0 ||
            result.byte_count != 0u) {
            owner->close_states[index] = SQ_LANE_UNCERTAIN;
            overall = SQ_OWNER_UNCERTAIN;
            continue;
        }
        if (result.error_code != 0) {
            owner->close_states[index] = SQ_LANE_FAILED;
            if (overall == SQ_OWNER_OK) {
                overall = SQ_OWNER_FAILED;
            }
            continue;
        }
        owner->close_states[index] = SQ_LANE_DONE;
        owner->closed_mask |= UINT32_C(1) << index;
    }
    return leave_owner(owner, overall);
}

int32_t sq_resolver_owner_write_control(
    void *storage,
    const uint8_t *bytes,
    uint32_t byte_count,
    uint64_t max_wait_ns
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result = {0u, 0u, 0, 0, 0u};
    int32_t boundary;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns) || bytes == NULL ||
        byte_count == 0u || byte_count > SQ_RESOLVER_MAX_CONTROL_BYTES) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = normal_state_locked(owner);
    if (status != SQ_OWNER_OK || (owner->closed_mask & UINT32_C(1)) != 0u) {
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (owner->control_state == SQ_LANE_DONE) {
        status = owner->control_byte_count == byte_count &&
            memcmp(owner->control_bytes, bytes, byte_count) == 0 ?
            SQ_OWNER_OK : SQ_OWNER_INVALID;
        return leave_owner(owner, status);
    }
    status = terminal_lane_status(owner->control_state);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    owner->control_state = SQ_LANE_IN_FLIGHT;
    boundary = owner->calls.write_control(
        owner->context,
        owner->fds[0],
        bytes,
        byte_count,
        max_wait_ns,
        &result
    );
    if (boundary != SQ_CALLBACK_RETURNED ||
        !action_result_shape_valid(&result) || result.value != 0 ||
        result.byte_count != 0u) {
        owner->control_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.outcome == SQ_ACTION_PENDING) {
        if (result.error_code != 0) {
            owner->control_state = SQ_LANE_UNCERTAIN;
            return leave_owner(owner, SQ_OWNER_UNCERTAIN);
        }
        owner->control_state = SQ_LANE_IDLE;
        return leave_owner(owner, SQ_OWNER_PENDING);
    }
    if (result.error_code != 0) {
        owner->control_state = SQ_LANE_FAILED;
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    memcpy(owner->control_bytes, bytes, byte_count);
    owner->control_byte_count = byte_count;
    owner->control_state = SQ_LANE_DONE;
    return leave_owner(owner, SQ_OWNER_OK);
}

static int copy_output_view_locked(
    struct sq_resolver_owner *owner,
    uint32_t maximum,
    uint8_t *bytes,
    uint32_t capacity,
    struct sq_resolver_output_view *view
) {
    if (owner->output_byte_count > maximum ||
        owner->output_byte_count > capacity) {
        return SQ_OWNER_INVALID;
    }
    if (owner->output_byte_count > 0u) {
        memcpy(bytes, owner->output_bytes, owner->output_byte_count);
    }
    view->magic = SQ_RESOLVER_OUTPUT_VIEW_MAGIC;
    view->sequence = owner->output_sequence;
    view->kind = owner->output_kind;
    view->byte_count = owner->output_byte_count;
    return SQ_OWNER_OK;
}

int32_t sq_resolver_owner_observe_output(
    void *storage,
    uint32_t maximum,
    uint8_t *bytes,
    uint32_t capacity,
    uint64_t max_wait_ns,
    struct sq_resolver_output_view *view
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result = {0u, 0u, 0, 0, 0u};
    uint8_t scratch[SQ_RESOLVER_MAX_OUTPUT_BYTES];
    uint32_t sequence;
    int32_t boundary;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns) || maximum == 0u ||
        maximum > SQ_RESOLVER_MAX_OUTPUT_BYTES || bytes == NULL ||
        capacity < maximum || view == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = normal_state_locked(owner);
    if (status != SQ_OWNER_OK ||
        (owner->closed_mask & (UINT32_C(1) << 1u)) != 0u) {
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (owner->output_slot_present != 0u) {
        status = copy_output_view_locked(owner, maximum, bytes, capacity, view);
        return leave_owner(owner, status);
    }
    status = terminal_lane_status(owner->output_state);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    sequence = owner->output_sequence;
    if (sequence >= SQ_RESOLVER_OUTPUT_COUNT) {
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    memset(scratch, 0, sizeof(scratch));
    owner->output_state = SQ_LANE_IN_FLIGHT;
    boundary = owner->calls.read_output(
        owner->context,
        owner->fds[1],
        sequence,
        scratch,
        maximum,
        max_wait_ns,
        &result
    );
    if (boundary != SQ_CALLBACK_RETURNED ||
        !action_result_shape_valid(&result)) {
        owner->output_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.outcome == SQ_ACTION_PENDING) {
        if (result.error_code != 0 || result.value != 0 ||
            result.byte_count != 0u) {
            owner->output_state = SQ_LANE_UNCERTAIN;
            return leave_owner(owner, SQ_OWNER_UNCERTAIN);
        }
        owner->output_state = SQ_LANE_IDLE;
        return leave_owner(owner, SQ_OWNER_PENDING);
    }
    if (result.error_code != 0) {
        owner->output_state = SQ_LANE_FAILED;
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (result.value < (int32_t)SQ_OUTPUT_READY ||
        result.value > (int32_t)SQ_OUTPUT_EOF || result.byte_count > maximum ||
        !output_payload_valid(
            sequence,
            (uint32_t)result.value,
            scratch,
            result.byte_count)) {
        owner->output_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.byte_count > 0u) {
        memcpy(owner->output_bytes, scratch, result.byte_count);
    }
    owner->output_kind = (uint32_t)result.value;
    owner->output_byte_count = result.byte_count;
    owner->output_slot_present = 1u;
    owner->output_state = SQ_LANE_DONE;
    status = copy_output_view_locked(owner, maximum, bytes, capacity, view);
    return leave_owner(owner, status);
}

int32_t sq_resolver_owner_ack_output(
    void *storage,
    uint32_t sequence,
    uint32_t kind,
    const uint8_t *bytes,
    uint32_t byte_count,
    const uint8_t digest[SQ_RESOLVER_DIGEST_BYTES]
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint64_t fingerprint;
    uint32_t bit;
    int status;

    if (!owner_valid(owner) || sequence >= SQ_RESOLVER_OUTPUT_COUNT ||
        kind != expected_output_kind(sequence) || bytes == NULL ||
        byte_count > SQ_RESOLVER_MAX_OUTPUT_BYTES || digest == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = normal_state_locked(owner);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    fingerprint = bytes_fingerprint(bytes, byte_count);
    bit = UINT32_C(1) << sequence;
    if ((owner->output_acked_mask & bit) != 0u) {
        status = owner->acked_kinds[sequence] == kind &&
            owner->acked_byte_counts[sequence] == byte_count &&
            owner->acked_fingerprints[sequence] == fingerprint &&
            memcmp(owner->acked_digests[sequence], digest,
                   SQ_RESOLVER_DIGEST_BYTES) == 0 ?
            SQ_OWNER_OK : SQ_OWNER_INVALID;
        return leave_owner(owner, status);
    }
    if (sequence != owner->output_sequence ||
        owner->output_slot_present == 0u || owner->output_kind != kind ||
        owner->output_byte_count != byte_count ||
        (byte_count > 0u &&
         memcmp(owner->output_bytes, bytes, byte_count) != 0)) {
        return leave_owner(owner, SQ_OWNER_INVALID);
    }
    owner->acked_kinds[sequence] = kind;
    owner->acked_byte_counts[sequence] = byte_count;
    owner->acked_fingerprints[sequence] = fingerprint;
    memcpy(owner->acked_digests[sequence], digest, SQ_RESOLVER_DIGEST_BYTES);
    owner->output_acked_mask |= bit;
    if (byte_count > 0u) {
        memset(owner->output_bytes, 0, byte_count);
    }
    owner->output_byte_count = 0u;
    owner->output_slot_present = 0u;
    owner->output_sequence = sequence + 1u;
    owner->output_state = SQ_LANE_IDLE;
    return leave_owner(owner, SQ_OWNER_OK);
}

int32_t sq_resolver_owner_check_liveness(
    void *storage,
    uint64_t max_wait_ns,
    int32_t *liveness_value
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    struct sq_resolver_action_result result = {0u, 0u, 0, 0, 0u};
    int32_t boundary;
    int status;

    if (!owner_valid(owner) || !wait_valid(max_wait_ns) ||
        liveness_value == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    status = normal_state_locked(owner);
    if (status != SQ_OWNER_OK ||
        (owner->closed_mask & (UINT32_C(1) << 3u)) != 0u) {
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (owner->liveness_state == SQ_LANE_DONE) {
        *liveness_value = owner->liveness_value;
        return leave_owner(owner, SQ_OWNER_OK);
    }
    status = terminal_lane_status(owner->liveness_state);
    if (status != SQ_OWNER_OK) {
        return leave_owner(owner, status);
    }
    owner->liveness_state = SQ_LANE_IN_FLIGHT;
    boundary = owner->calls.check_liveness(
        owner->context,
        owner->fds[3],
        max_wait_ns,
        &result
    );
    if (boundary != SQ_CALLBACK_RETURNED ||
        !action_result_shape_valid(&result) || result.byte_count != 0u) {
        owner->liveness_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    if (result.outcome == SQ_ACTION_PENDING) {
        if (result.error_code != 0 || result.value != 0) {
            owner->liveness_state = SQ_LANE_UNCERTAIN;
            return leave_owner(owner, SQ_OWNER_UNCERTAIN);
        }
        owner->liveness_state = SQ_LANE_IDLE;
        return leave_owner(owner, SQ_OWNER_PENDING);
    }
    if (result.error_code != 0) {
        owner->liveness_state = SQ_LANE_FAILED;
        return leave_owner(owner, SQ_OWNER_FAILED);
    }
    if (result.value != 0 && result.value != 1) {
        owner->liveness_state = SQ_LANE_UNCERTAIN;
        return leave_owner(owner, SQ_OWNER_UNCERTAIN);
    }
    owner->liveness_value = result.value;
    owner->liveness_state = SQ_LANE_DONE;
    *liveness_value = owner->liveness_value;
    return leave_owner(owner, SQ_OWNER_OK);
}

int32_t sq_resolver_owner_snapshot(
    void *storage,
    struct sq_resolver_owner_snapshot *snapshot
) {
    struct sq_resolver_owner *owner = (struct sq_resolver_owner *)storage;
    uint32_t publication;
    uint32_t state;
    uint32_t index;

    if (!owner_valid(owner) || snapshot == NULL) {
        return SQ_OWNER_INVALID;
    }
    if (enter_owner(owner) != SQ_OWNER_OK) {
        return SQ_OWNER_BUSY;
    }
    state = atomic_load_explicit(&owner->state, memory_order_acquire);
    publication = atomic_load_explicit(
        &owner->publication,
        memory_order_acquire
    );
    if (publication == SQ_PUBLICATION_WRITING) {
        return leave_owner(owner, SQ_OWNER_BUSY);
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->magic = SQ_RESOLVER_SNAPSHOT_MAGIC;
    snapshot->state = state;
    snapshot->publication = publication;
    snapshot->uncertainty_reason = owner->uncertainty_reason;
    if ((state == SQ_STATE_CONSTRUCTING ||
         state == SQ_STATE_CREATE_UNCERTAIN) &&
        (publication == SQ_PUBLICATION_CREATED ||
         publication == SQ_PUBLICATION_INVALID)) {
        snapshot->pid = atomic_load_explicit(
            &owner->published_pid,
            memory_order_relaxed
        );
        for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
            snapshot->fds[index] = atomic_load_explicit(
                &owner->published_fds[index],
                memory_order_relaxed
            );
        }
    } else {
        snapshot->pid = owner->pid;
        for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
            snapshot->fds[index] = owner->fds[index];
        }
    }
    for (index = 0u; index < SQ_RESOLVER_FD_COUNT; index += 1u) {
        snapshot->close_states[index] = owner->close_states[index];
    }
    snapshot->closed_mask = owner->closed_mask;
    snapshot->signal_state = owner->signal_state;
    snapshot->wait_state = owner->wait_state;
    snapshot->wait_status = owner->wait_status;
    snapshot->control_state = owner->control_state;
    snapshot->next_output_sequence = owner->output_sequence;
    snapshot->output_state = owner->output_state;
    snapshot->output_slot_present = owner->output_slot_present;
    snapshot->output_slot_kind = owner->output_kind;
    snapshot->output_slot_bytes = owner->output_byte_count;
    snapshot->output_acked_mask = owner->output_acked_mask;
    snapshot->liveness_state = owner->liveness_state;
    snapshot->liveness_value = owner->liveness_value;
    return leave_owner(owner, SQ_OWNER_OK);
}
