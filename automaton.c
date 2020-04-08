/*
 *
 * Copyright 2020 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#include "api/libautomaton.h"
#include "libc/types.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/semaphore.h"
#include "libc/random.h"

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK || CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
#include "libfw.h"
#endif

/*
 * secure boolean, not exactly inverted, with a Hamming distance long enough
 */
typedef enum {
    SECURE_FALSE = 0xacefaecf,
    SECURE_TRUE =  0xca38c3e8
} secure_bool_t;

/*
 * Due to secure automaton properties, only 16 states are supported.
 * This sould be enough for most of existing state automaton.
 * If more state are requested, the state_translation_tab[] must be increased.
 */
#define MAX_AUTOMATON_STATES 16

/*
 * Due to secure automaton properties, only 32 transitions are supported.
 * This sould be enough for most of existing state automaton.
 * If more transitions are requested, the transition_translation_tab[] must be increased.
 */
#define MAX_AUTOMATON_TRANSITIONS 32

#define AUTOMATON_DEBUG CONFIG_USR_LIB_AUTOMATON_DEBUG

#if AUTOMATON_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif


typedef uint32_t secure_state_id_t;
typedef uint64_t secure_transition_id_t;



/*
 * We consider that states (state_id_t) are defined from 0 to n-1, n being the
 * number of states defined.
 * The tab cell identifier correspond to the state_id_t, the cell content being
 * the secure_state_id_t used in the automaton library.
 */
static const secure_state_id_t state_translate_tab[] = {
    0x00000003,
    0x0000000c,
    0x00000035,
    0x000000ca,
    0x00000350,
    0x00000ca3,
    0x000035cf,
    0x0000ca0c,
    0x00035c30,
    0x000ca3f3,
    0x0035cfcf,
    0x00ca5050,
    0x035cacac,
    0x0ca5c5cf,
    0x35c30f3c,
    0xcaacfcfa,
};

/*
 * We consider that transitions (transition_id_t) are defined from 0 to m-1, m being the
 * number of transitions defined.
 * The tab cell identifier correspond to the transition_id_t, the cell content being
 * the secure_transition_id_t used in the automaton library.
 */

static const secure_transition_id_t transition_translate_tab[] = {
    0x4501b87688a05cdb,
    0x5bfaa247365fc460,
    0x407abd7d59626eb0,
    0xece34c559185f4d4,
    0x5f0624ca3421364d,
    0x8a4b7369e1c52b9c,
    0x42e1ec5f1611d389,
    0xa32395bf1acf2e76,
    0x4c91599f3168ea9c,
    0x0ce39a5b292e03ae,
    0x8f6da32bb81e6eca,
    0x5e22ad21265b1bcb,
    0xad835b4c8f2b3e8b,
    0xe7182ea591202939,
    0x867efe6fd601d8d5,
    0x0e2ff92da50f157f,
    0x55a7f94d72356290,
    0x4945d9e922651672,
    0x2244e60833d23283,
    0x2c75887686440b14,
    0x1f02ba2bf6524a2f,
    0x6d8547d0737d4947,
    0x15c558fa3f891e46,
    0x1e6d9bc61a99d94a,
    0xdc3cb23f6ba7e2ba,
    0xc676b68eb329bea0,
    0xd89781d206de2bb9,
    0x9ebbb9c4a99e5fd6,
    0x74afd9d4e6a870fa,
    0xf3760ef6c4ef9fb5,
    0xa9c245d8e98c1bb7,
    0x031a97402caaf6a8,
};



/****************************************************************
 * state automaton formal definition and associate utility
 * functions
 ***************************************************************/

/*
 * The libautomaton is reentrant and associated to contexts. This allows
 * a given tasks to handle as many context as needed.
 *
 * The automaton state is volatile and support preemption.
 * TODO: a lock on state write must be added to support properly reentrancy
 * (i.e. blocking ? we hould decide about ISR case)
 */
typedef struct {
    uint8_t             state_number;               /*< number of state for automaton */
    uint8_t             transition_number;          /*< number of transition for automaton */
    volatile secure_state_id_t state;                      /*< current state */
    uint8_t             max_transitions_per_state;  /*< max number of transition per state */
    const automaton_transition_t * const * state_automaton; /*< declared state automaton */
    volatile uint32_t   state_lock;                /*< state WR access lock */

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    uint32_t            crc;
#endif
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
    volatile uint64_t   controlflow;
    volatile uint64_t   currentflow;
#endif
} automaton_context_t;

typedef struct {
    volatile uint32_t   lock;
    uint8_t             ctx_num;
    secure_bool_t       initialized;
    automaton_context_t contexts[CONFIG_USR_LIB_AUTOMATON_MAX_CONTEXT_NUM];
} automaton_ctx_vector_t;

/*
 * all set to 0. By default, global libautomaton context is set as not initialized.
 */
static volatile automaton_ctx_vector_t ctx_vector = { 0 };

/**********************************************
 * automaton local utility functions
 *********************************************/

#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
static inline void update_controlflowvar(volatile uint64_t *var, uint32_t value)
{
    /* atomic local update of the control flow var.
     * FIXME: addition is problematic because it does not ensure that
     * previous states has been executed in the correct order, but only
     * that they **all** have been executed. Though, as each state check for
     * the control flow, the order is checked. Althgouh, a mathematical
     * primitive ensuring variation (successive CRC ? other ?) would be better. */
    *var += crc32((unsigned char*)&value, sizeof(value), 0xffffffff);

}
#endif



/* About context vector handling */
static inline secure_bool_t automaton_ctx_exists(const automaton_ctx_handler_t ctxh)
{
    if (ctxh >= ctx_vector.ctx_num) {
        return false;
    }
    return true;
}

static inline automaton_context_t *automaton_get_context(const automaton_ctx_handler_t ctxh)
{
    /* here we consider ctxh valid, as this function is called internally in the
     * automaton libs, where ctxh is check *before* this call */
    return (automaton_context_t *)&(ctx_vector.contexts[ctxh]);
}


/* About a given context automaton handling */
static inline secure_bool_t automaton_state_exists(const automaton_context_t * const ctx, const state_id_t state)
{
    if (state >= ctx->state_number) {
        return false;
    }
    return true;
}

static inline secure_bool_t automaton_transition_exists(const automaton_context_t * const ctx, const transition_id_t transition)
{
    if (transition >= ctx->transition_number) {
        return false;
    }
    return true;
}


static secure_state_id_t automaton_convert_state(state_id_t state)
{
    if (state < MAX_AUTOMATON_STATES) {
        return state_translate_tab[state];
    }
    return 0;
}

static secure_transition_id_t automaton_convert_transition(transition_id_t transition)
{
    if (transition < MAX_AUTOMATON_TRANSITIONS) {
        return transition_translate_tab[transition];
    }
    return 0;
}

static state_id_t automaton_convert_secure_state(secure_state_id_t state)
{
    for (uint8_t i = 0; i < MAX_AUTOMATON_STATES; ++i) {
        if (state_translate_tab[i] == state) {
            return i;
        }
    }
    /* use mbed_error_t instead */
    return 0;
}

static transition_id_t automaton_convert_secure_transition(secure_transition_id_t transition)
{
    for (uint8_t i = 0; i < MAX_AUTOMATON_TRANSITIONS; ++i) {
        if (transition_translate_tab[i] == transition) {
            return i;
        }
    }
    /* use mbed_error_t instead */
    return 0;
}


/**********************************************
 * automaton getters and setters
 *********************************************/

/*
 * initialize the libautomaton context.
 * - initialize the mutex
 * - set ctx_num to 0
 * -et context as initialized
 */
mbed_error_t automaton_initialize(void)
{
    mutex_init(&ctx_vector.lock);
    ctx_vector.ctx_num = 0;
    ctx_vector.initialized = SECURE_TRUE;
    return MBED_ERROR_NONE;
}

mbed_error_t automaton_declare_context(__in  const uint8_t num_states,
                                       __in  const uint8_t num_transition,
                                       __in  const uint8_t max_transition_per_state,
                                       __in  const automaton_transition_t * const * const state_automaton,
                                       __out automaton_ctx_handler_t *ctxh)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /*sanitize */
    if (ctx_vector.initialized != SECURE_TRUE) {
        return MBED_ERROR_INVSTATE;
    }
    if (!ctxh) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (ctx_vector.ctx_num == CONFIG_USR_LIB_AUTOMATON_MAX_CONTEXT_NUM) {
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    if (num_states > MAX_AUTOMATON_STATES) {
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    if (num_transition > MAX_AUTOMATON_TRANSITIONS) {
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    automaton_context_t *ctx = NULL;
    ctx = automaton_get_context(ctx_vector.ctx_num);

    mutex_lock(&ctx_vector.lock);

    mutex_init(&ctx->state_lock);
    ctx->state_number = num_states;
    ctx->transition_number = num_transition;
    ctx->max_transitions_per_state = max_transition_per_state;
    ctx->state_automaton = state_automaton;

    mutex_unlock(&ctx_vector.lock);

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    uint32_t crc = 0xffffffff;
    crc = crc32((unsigned char*)&num_states, sizeof(num_states), crc);
    crc = crc32((unsigned char*)&num_transition, sizeof(num_transition), crc);
    crc = crc32((unsigned char*)&max_transitions_per_state, sizeof(max_transitions_per_state), crc);
    crc = crc32((unsigned char*)&state_automaton, sizeof(state_automaton), crc);
    uint32_t crc_ctx = 0xffffffff;
    crc_ctx = crc32((unsigned char*)&ctx->state_number, sizeof(num_states), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->transition_number, sizeof(num_transition), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->max_transitions_per_state, sizeof(max_transitions_per_state), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->state_automaton, sizeof(state_automaton), crc_ctx);
    /* hardened if */
    if (crc != crc_ctx &&
        !(crc == crc_ctx)) {
        log_printf("[automaton] invalid data integrity check: crc32: %x != %x\n", crc, crc_ctx);
        errcode = MBED_ERROR_WRERROR;
        goto err;
    }
#endif
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
    get_random((unsigned char*)&ctx->controlflow, sizeof(ctx->controlflow));
    ctx->currentflow = ctx->controlflow;
#endif
    ctx_vector.ctx_num++;
err:
    return errcode;
}

state_id_t automaton_get_state(__in  const automaton_ctx_handler_t ctxh,
                               __out state_id_t                   *state)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    if (ctx_vector.initialized != SECURE_TRUE) {
        return MBED_ERROR_INVSTATE;
    }
    if (!automaton_ctx_exists(ctxh)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (!state) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    ctx = automaton_get_context(ctxh);
    *state = automaton_convert_state(ctx->state);
err:
    return errcode;
}


mbed_error_t automaton_set_state(const automaton_ctx_handler_t ctxh,
                                 const state_id_t new_state)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    automaton_context_t *ctx = NULL;

    if (ctx_vector.initialized != SECURE_TRUE) {
        return MBED_ERROR_INVSTATE;
    }
    if (!automaton_ctx_exists(ctxh)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    ctx = automaton_get_context(ctxh);

    if (automaton_state_exists(ctx, new_state) == SECURE_FALSE &&
        !(automaton_state_exists(ctx, new_state) != SECURE_FALSE)) {
        goto err;
    }

    mutex_lock(&ctx->state_lock);
    ctx->state = automaton_convert_state(new_state);
    /* hardening assignation */
    if (ctx->state != automaton_convert_state(new_state) &&
        !(ctx->state == automaton_convert_state(new_state))) {
        errcode = MBED_ERROR_WRERROR;
        goto err;
    }
    mutex_unlock(&ctx->state_lock);
    log_printf("%s: state: %x => %x\n", __func__, ctx->state, new_state);
err:
    return errcode;
}

/******************************************************
 * automaton management function (transition and state check)
 *****************************************************/

/*!
 * \brief return the next automaton state
 *
 * The next state is returned depending on the current state
 * and the current request. In some case, it can be 0xff if multiple
 * next states are possible.
 *
 * \param [in]  ctxh          the current automaton context handler
 * \param [in]  current_state the current automaton state
 * \param [in]  request       the current transition request
 * \param [out] newstate      the next state, set by the function, if the transition is
 *                            predictable
 *
 * \return MBED_ERROR_NONE if the transition is predictable, or MBED_ERROR_UNKNOWN if
 *         the newstate is not predictable.
 */
mbed_error_t automaton_get_next_state(__in  const automaton_ctx_handler_t     ctxh,
                                      __in  const state_id_t                  current_state,
                                      __in  const transition_id_t             transition,
                                      __out state_id_t                       *newstate)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    if (ctx_vector.initialized != SECURE_TRUE) {
        return MBED_ERROR_INVSTATE;
    }
    if (!automaton_ctx_exists(ctxh)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    ctx = automaton_get_context(ctxh);

    if (automaton_state_exists(ctx, current_state) == SECURE_FALSE &&
        !(automaton_state_exists(ctx, current_state) != SECURE_FALSE)) {
        goto err;
    }
    if (automaton_transition_exists(ctx, transition) == SECURE_FALSE &&
        !(automaton_transition_exists(ctx, transition) != SECURE_FALSE)) {
        goto err;
    }

    for (uint8_t i = 0; i < ctx->max_transitions_per_state; ++i) {
        /* hardened if, requiring O0 */
        if (ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].transition_id == transition &&
            !(ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].transition_id != transition)) {

            if (ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].predictable) {
                *newstate = ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].target_state;
                goto err;
            } else {
                errcode = MBED_ERROR_UNKNOWN;
                goto err;
            }
        }
    }
err:
    return errcode;
}

/*!
 * \brief Specify if the current request is valid for the current state
 *
 * \param [in] ctxh          the current automaton context handler
 * \param [in] current_state the current automaton state
 * \param [in] request       the current transition request
 *
 * \return true if the transition request is allowed for this state, or false
 */
bool automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
                                   __in  const state_id_t                  current_state,
                                   __in  const transition_id_t             transition)
{
    bool result = false;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    /* the first initialization steps are not hardened as a fault on these if will simply generated
     * a memory fault */
    if (ctx_vector.initialized != SECURE_FALSE) {
        goto err;
    }
    if (!automaton_ctx_exists(ctxh)) {
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    /* from now on, if must be doubled to avoid potential fault which may generate dangerous invalid
     * behavior */
    if (automaton_state_exists(ctx, current_state) == SECURE_FALSE &&
        !(automaton_state_exists(ctx, current_state) != SECURE_FALSE)) {
        goto err;
    }
    if (automaton_transition_exists(ctx, transition) == SECURE_FALSE &&
        !(automaton_transition_exists(ctx, transition) != SECURE_FALSE)) {
        goto err;
    }

    /* TODO: get next state on state automaton */
    for (uint8_t i = 0; i < ctx->max_transitions_per_state; ++i) {

        /* hardened if, requiring O0 */
        if (ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].transition_id == transition &&
            !(ctx->state_automaton[automaton_convert_state(ctx->state)]->transition[i].transition_id != transition)) {

            result = true;
            goto err;
        }
    }

err:
    return result;
}

#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
secbool automaton_calculate_flowstate(const  automaton_context_t * const ctx,
                                      state_id_t prevstate,
                                      state_id_t nextstate)
{
    /*
     * Here, we recalculate from scratch, based on the prevstate/nextstate pair
     * (which **must** be unique) to current controlflow value.
     * We use the flow control sequence set in .rodata to successively increment
     * myflow up to the state pair we should be on.
     * The caller function can then compare the result of this function with
     * loader_update_flowstate(). If the results are the same, the control flow is
     * keeped. If not, the control flow is corrupted.
     */
    /* 1. init myflow to seed */
    uint64_t myflow = (uint64_t)ctx->controlflow;
    /* 3. found state pair ? add nextstate en return */
    // To update to support loops, unpredictable cases and so on.
    // To do that, we must color the reverse path, of a state, memorise it and
    // calculate the reverse-reverse path from the root node.
    // The other method is to keep the memory of each state reached somewhere in
    // a stack allowing the full calculation
    prevstate = prevstate;

    update_controlflowvar(&myflow, automaton_convert_state(nextstate));

    log_printf("%s: result of online calculation (%d sequences) is (long long) %ll\n", __func__, i, myflow);
    /* TODO: how to harden u64 comparison ? */
    if (myflow != ctx->currentflow) {
        /* control flow error detected */
        log_printf("Error in control flow ! Fault injection detected !\n");
        return SECURE_FALSE;
    }
    return SECURE_TRUE;
}

void automaton_update_flowstate(automaton_context_t *ctx, state_id_t nextstate)
{
    /* here, we update current flow in order to add the current state to the previous
     * flow sequence, by adding its state value to the currentflow variable */
    /* calculation may be more complex to avoid any collision risk. Is there a way
     * through cryptographic calculation on state value concatenation to avoid any
     * risk ? */
    update_controlflowvar(&ctx->currentflow, automaton_convert_state(nextstate));
    log_printf("%s: update controlflow to (long long) %ll\n", __func__, ctx->currentflow);

}
#endif
