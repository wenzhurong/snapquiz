#include <errno.h>
#include <stddef.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/*
 * Narrow native publication cell for the S2b-I2 development foundation.
 *
 * posix_spawn(3) may create a child immediately before Python is interrupted
 * while publishing the return value.  This shim commits the syscall result
 * and PID to caller-owned memory before returning across the language
 * boundary.  It does not own signalling, waitpid, descriptors, descendants,
 * or the production bundle lifecycle; those remain later native/XPC gates.
 */

#define SQ_SPAWN_OUTCOME_ABI 0x53514932u
#define SQ_SPAWN_OUTCOME_NEW 0u
#define SQ_SPAWN_OUTCOME_IN_FLIGHT 1u
#define SQ_SPAWN_OUTCOME_COMMITTED 2u
#define SQ_SPAWN_OUTCOME_MAGIC 0x5351504fu

struct sq_spawn_outcome {
    uint32_t abi;
    _Atomic uint32_t state;
    int32_t result;
    int32_t pid;
    uint32_t magic;
};

#if ATOMIC_INT_LOCK_FREE != 2
#error "darwin spawn outcome requires lock-free 32-bit atomics"
#endif

_Static_assert(sizeof(pid_t) <= sizeof(int32_t), "pid_t does not fit int32_t");
_Static_assert(
    sizeof(_Atomic uint32_t) == sizeof(uint32_t),
    "atomic state width does not match uint32_t"
);
_Static_assert(offsetof(struct sq_spawn_outcome, abi) == 0, "abi offset mismatch");
_Static_assert(offsetof(struct sq_spawn_outcome, state) == 4, "state offset mismatch");
_Static_assert(offsetof(struct sq_spawn_outcome, result) == 8, "result offset mismatch");
_Static_assert(offsetof(struct sq_spawn_outcome, pid) == 12, "pid offset mismatch");
_Static_assert(offsetof(struct sq_spawn_outcome, magic) == 16, "magic offset mismatch");
_Static_assert(sizeof(struct sq_spawn_outcome) == 20, "outcome size mismatch");

int32_t sq_posix_spawn_publish(
    struct sq_spawn_outcome *outcome,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
) {
    pid_t pid = 0;
    int result;

    if (outcome == NULL || path == NULL || argv == NULL || envp == NULL ||
        outcome->abi != SQ_SPAWN_OUTCOME_ABI ||
        atomic_load_explicit(&outcome->state, memory_order_acquire) !=
            SQ_SPAWN_OUTCOME_NEW) {
        return EINVAL;
    }
    outcome->result = INT32_MIN;
    outcome->pid = 0;
    outcome->magic = 0;
    atomic_store_explicit(
        &outcome->state,
        SQ_SPAWN_OUTCOME_IN_FLIGHT,
        memory_order_release
    );
    result = posix_spawn(
        &pid,
        path,
        file_actions,
        attributes,
        argv,
        envp
    );
    outcome->result = (int32_t)result;
    outcome->pid = result == 0 ? (int32_t)pid : 0;
    outcome->magic = SQ_SPAWN_OUTCOME_MAGIC;
    atomic_store_explicit(
        &outcome->state,
        SQ_SPAWN_OUTCOME_COMMITTED,
        memory_order_release
    );
    return 0;
}
