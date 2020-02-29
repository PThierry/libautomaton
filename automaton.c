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
#include "libautomaton.h"
#include "libc/types.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/semaphore.h"

#define AUTOMATON_DEBUG CONFIG_USR_LIB_AUTOMATON_DEBUG

#if AUTOMATON_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif



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
    volatile state_id_t state;                      /*< current state */
    uint8_t             max_transitions_per_state;  /*< max number of transition per state */
    const automaton_transition_t * const * state_automaton; /*< declared state automaton */
    volatile uint32_t   state_lock;                /*< state WR access lock */

} automaton_context_t;

typedef struct {
    volatile uint32_t   lock;
    uint8_t             ctx_num;
    bool                initialized;
    automaton_context_t contexts[CONFIG_USR_LIB_AUTOMATON_MAX_CONTEXT_NUM];
} automaton_ctx_vector_t;

/*
 * all set to 0. By default, global libautomaton context is set as not initialized.
 */
static volatile automaton_ctx_vector_t ctx_vector = { 0 };

/**********************************************
 * automaton local utility functions
 *********************************************/

/* About context vector handling */
static inline bool automaton_ctx_exists(const automaton_ctx_handler_t ctxh)
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
static inline bool automaton_state_exists(const automaton_context_t * const ctx, const state_id_t state)
{
    if (state >= ctx->state_number) {
        return false;
    }
    return true;
}

static inline bool automaton_transition_exists(const automaton_context_t * const ctx, const transition_id_t transition)
{
    if (transition >= ctx->transition_number) {
        return false;
    }
    return true;
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
    ctx_vector.initialized = true;
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
    if (ctx_vector.initialized != true) {
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
    automaton_context_t *ctx = NULL;
    ctx = automaton_get_context(ctx_vector.ctx_num);

    mutex_lock(&ctx_vector.lock);

    mutex_init(&ctx->state_lock);
    ctx->state_number = num_states;
    ctx->transition_number = num_transition;
    ctx->max_transitions_per_state = max_transition_per_state;
    ctx->state_automaton = state_automaton;

    mutex_unlock(&ctx_vector.lock);

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
    if (ctx_vector.initialized != true) {
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
    *state = ctx->state;
err:
    return errcode;
}


mbed_error_t automaton_set_state(const automaton_ctx_handler_t ctxh,
                                 const state_id_t new_state)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    automaton_context_t *ctx = NULL;

    if (ctx_vector.initialized != true) {
        return MBED_ERROR_INVSTATE;
    }
    if (!automaton_ctx_exists(ctxh)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (!automaton_state_exists(ctx, new_state)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    mutex_lock(&ctx->state_lock);
    ctx->state = new_state;
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
    if (ctx_vector.initialized != true) {
        return MBED_ERROR_INVSTATE;
    }
    if (!automaton_ctx_exists(ctxh)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (!automaton_state_exists(ctx, current_state)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (!automaton_transition_exists(ctx, transition)) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    for (uint8_t i = 0; i < ctx->max_transitions_per_state; ++i) {
        if (ctx->state_automaton[ctx->state]->transition[i].transition_id == transition) {
            if (ctx->state_automaton[ctx->state]->transition[i].predictable) {
                *newstate = ctx->state_automaton[ctx->state]->transition[i].target_state;
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
    if (ctx_vector.initialized != true) {
        goto err;
    }
    if (!automaton_ctx_exists(ctxh)) {
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (!automaton_state_exists(ctx, current_state)) {
        goto err;
    }
    if (!automaton_transition_exists(ctx, transition)) {
        goto err;
    }

    /* TODO: get next state on state automaton */
    for (uint8_t i = 0; i < ctx->max_transitions_per_state; ++i) {
        if (ctx->state_automaton[ctx->state]->transition[i].transition_id == transition) {
            result = true;
            goto err;
        }
    }

err:
    return result;
}
