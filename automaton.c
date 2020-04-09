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
#include "automaton_data_integrity.h"
#include "automaton.h"

#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
#include "libfw.h"
#endif


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
 * all set to 0. By default, global libautomaton context is set as not initialized.
 */
static volatile automaton_ctx_vector_t ctx_vector = { 0 };

/**********************************************
 * automaton local utility functions
 *********************************************/


/* About context vector handling */
secure_bool_t automaton_ctx_exists(const automaton_ctx_handler_t ctxh)
{
    if (ctx_vector.initialized != SECURE_TRUE) {
        return SECURE_FALSE;
    }
    if (ctxh >= ctx_vector.ctx_num) {
        return SECURE_FALSE;
    }
    return SECURE_TRUE;
}

automaton_context_t *automaton_get_context(const automaton_ctx_handler_t ctxh)
{
    /* here we consider ctxh valid, as this function is called internally in the
     * automaton libs, where ctxh is check *before* this call */
    return (automaton_context_t *)&(ctx_vector.contexts[ctxh]);
}


/* About a given context automaton handling */
secure_bool_t automaton_state_exists(const automaton_context_t * const ctx, const state_id_t state)
{
    if (state >= ctx->state_number) {
        return false;
    }
    return true;
}

secure_bool_t automaton_transition_exists(const automaton_context_t * const ctx, const transition_id_t transition)
{
    if (transition >= ctx->transition_number) {
        return false;
    }
    return true;
}


secure_state_id_t automaton_convert_state(state_id_t state)
{
    if (state < MAX_AUTOMATON_STATES) {
        return state_translate_tab[state];
    }
    return 0;
}

secure_transition_id_t automaton_convert_transition(transition_id_t transition)
{
    if (transition < MAX_AUTOMATON_TRANSITIONS) {
        return transition_translate_tab[transition];
    }
    return 0;
}

state_id_t automaton_convert_secure_state(secure_state_id_t state)
{
    for (uint8_t i = 0; i < MAX_AUTOMATON_STATES; ++i) {
        if (state_translate_tab[i] == state) {
            return i;
        }
    }
    /* use mbed_error_t instead */
    return 0;
}

transition_id_t automaton_convert_secure_transition(secure_transition_id_t transition)
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
    if (automaton_calculate_context_integrity(ctx, &ctx->crc) != MBED_ERROR_NONE) {
        log_printf("[automaton] %s:unable to calculate CRC!\n", __func__);
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
#endif
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
    memset((void*)&ctx->req, 0x0, sizeof(automaton_transition_request_t));
    ctx->waiting_req = SECURE_FALSE;
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
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
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
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
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
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
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
secure_bool_t automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
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
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
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


