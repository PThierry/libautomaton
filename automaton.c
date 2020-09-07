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

#if AUTOMATON_DEBUG
/* logging space optimization: redundant strings are stored in a tab, associated to
 * an enumerate, this could be pushed to a dedicated debug file */
static const char *log_tab[] = {
    "[automaton]",
    "not initialized!",
    "invalid",
    "inexistant",
    "not found",
    "state",
    "transition",
    "context",
};

enum log_tab_id {
    LIBNAME = 0,
    NOT_INIT,
    INVALID,
    INEXISTANT,
    NOTFOUND,
    STATE,
    TRANSITION,
    CONTEXT,
};
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
#if defined(__FRAMAC__)
static automaton_ctx_vector_t ctx_vector = { 0 };
#else
static automaton_ctx_vector_t ctx_vector = { 0 };
#endif

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

/*@
  @ assigns \nothing;
  @
  @ behavior bad_entries:
  @    assumes (ctxh >= ctx_vector.ctx_num || ctx_vector.initialized != SECURE_TRUE);
  @    ensures \result == NULL;
  @
  @ behavior good_entries:
  @    assumes (0 <= ctxh < ctx_vector.ctx_num && ctx_vector.initialized == SECURE_TRUE);
  @    ensures \valid(\result);
  @
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
automaton_context_t *automaton_get_context(const automaton_ctx_handler_t ctxh)
{
    automaton_context_t *ctx = NULL;
    if (ctx_vector.initialized != SECURE_TRUE) {
        log_printf("%s: %s you must initialize first!\n", log_tab[LIBNAME], __func__);
        goto err;
    }
    if (ctxh >= ctx_vector.ctx_num) {
        log_printf("%s: %s context invalid\n", log_tab[LIBNAME], __func__);
        goto err;
    }
    /* here we consider ctxh valid, as this function is called internally in the
     * automaton libs, where ctxh is check *before* this call */

    ctx = (automaton_context_t *)&(ctx_vector.contexts[ctxh]);
    /*@ assert \valid(ctx); */
err:
    return ctx;
}


/* About a given context automaton handling */

/*@
  @  requires \valid(ctx);
  @  requires state >= 0;
  @  ensures ctx->state_number < state ==> \result == SECURE_FALSE;
  @  ensures 0 <= state < ctx->state_number ==> \result == SECURE_FALSE;
  @  assigns \nothing;
  @*/
secure_bool_t automaton_state_exists(const automaton_context_t * const ctx, const state_id_t state)
{
    log_printf("%s\n", __func__);
    secure_bool_t res = SECURE_FALSE;
    if (ctx == NULL) {
        goto err;
    }
    if (state >= ctx->state_number) {
        goto err;
    }
    res = SECURE_TRUE;
err:
    return res;
}

/*@
  @  requires \valid(ctx);
  @  requires transition >= 0;
  @  ensures ctx->transition_number < transition ==> \result == SECURE_FALSE;
  @  ensures 0 <= transition < ctx->transition_number ==> \result == SECURE_FALSE;
  @*/
secure_bool_t automaton_transition_exists(const automaton_context_t * const ctx, const transition_id_t transition)
{
    log_printf("%s\n", __func__);
    secure_bool_t res = SECURE_FALSE;
    if (ctx == NULL) {
        goto err;
    }
    if (transition >= ctx->transition_number) {
        goto err;
    }
    res =  SECURE_TRUE;
err:
    return res;
}

/*@
  @  ensures 0 <= state < MAX_AUTOMATON_STATES
  @      ==> \result == state_translate_tab[state];
  @  ensures state >= MAX_AUTOMATON_STATES
  @      ==> \result == 0;
  @*/
secure_state_id_t automaton_convert_state(state_id_t state)
{
    if (state < MAX_AUTOMATON_STATES) {
        return state_translate_tab[state];
    }
    return 0;
}

/*@
  @  ensures 0 <= transition < MAX_AUTOMATON_TRANSITIONS
  @      ==> \result == transition_translate_tab[transition];
  @  ensures transition >= MAX_AUTOMATON_TRANSITIONS
  @      ==> \result == 0;
  @*/
secure_transition_id_t automaton_convert_transition(transition_id_t transition)
{
    if (transition < MAX_AUTOMATON_TRANSITIONS) {
        return transition_translate_tab[transition];
    }
    return 0;
}

/*@
  @  ensures 0 <= state < MAX_AUTOMATON_STATES;
  @  assigns \nothing;
  @  ensures \result == MAX_AUTOMATON_STATES
  @     ==> (\forall integer i; 0 <= i < MAX_AUTOMATON_STATES ==> state_translate_tab[i] != state);
  @  ensures 0 <= \result < MAX_AUTOMATON_STATES ==> state_translate_tab[\result] == state;
  @*/
state_id_t automaton_convert_secure_state(secure_state_id_t state)
{
    uint8_t i = 0;
    state_id_t result = MAX_AUTOMATON_STATES;
    /*@ loop invariant 0 <= i <= MAX_AUTOMATON_STATES;
      @ loop invariant \forall integer j; 0 <= j < i ==> state_translate_tab[i] != state;
      @ loop assigns i;
      @ loop variant MAX_AUTOMATON_STATES - i;
      @*/
    for (i = 0; i < MAX_AUTOMATON_STATES; ++i) {
        if (state_translate_tab[i] == state) {
            result = i;
            break;
        }
    }
    /* use mbed_error_t instead */
    return result;
}

/*@
  @  ensures 0 <= transition < MAX_AUTOMATON_TRANSITIONS;
  @  assigns \nothing;
  @  ensures \result == MAX_AUTOMATON_TRANSITIONS
  @     ==> (\forall integer i; 0 <= i < MAX_AUTOMATON_TRANSITIONS ==> transition_translate_tab[i] != transition);
  @  ensures 0 <= \result < MAX_AUTOMATON_TRANSITIONS
  @     ==> transition_translate_tab[\result] == transition;
  @*/
transition_id_t automaton_convert_secure_transition(secure_transition_id_t transition)
{
    uint8_t i = 0;
    transition_id_t result = MAX_AUTOMATON_TRANSITIONS;
    /*@ loop invariant 0 <= i <= MAX_AUTOMATON_TRANSITIONS;
      @ loop invariant \forall integer j; 0 <= j < i ==> transition_translate_tab[i] != transition;
      @ loop assigns i;
      @ loop variant MAX_AUTOMATON_TRANSITIONS - i;
      @*/
    for (i = 0; i < MAX_AUTOMATON_TRANSITIONS; ++i) {
        if (transition_translate_tab[i] == transition) {

            result = i;
            break;
        }
    }
    /* invalid here, 0 is a valid cell. use mbed_error_t instead */
    return result;
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

/* TODO: crc check not added to good_entries behavior */
/*@
  @ ensures state_automaton == NULL
  @   ==> \result == MBED_ERROR_INVPARAM;
  @ ensures ctx_vector.initialized != SECURE_TRUE
  @   ==> \result == MBED_ERROR_INVSTATE;
  @ ensures num_states > MAX_AUTOMATON_STATES
  @   ==> \result == MBED_ERROR_NOMEM;
  @ ensures num_transition > MAX_AUTOMATON_TRANSITIONS
  @   ==> \result == MBED_ERROR_NOMEM;
  @
  @ behavior bad_entries:
  @     assumes (state_automaton == NULL ||
  @              num_states > MAX_AUTOMATON_STATES ||
  @              ctx_vector.initialized != SECURE_TRUE ||
  @              num_states > MAX_AUTOMATON_STATES ||
  @              num_transition > MAX_AUTOMATON_TRANSITIONS);
  @     assigns \nothing;
  @ behavior good_entries:
  @     assumes !(state_automaton == NULL ||
  @                num_states > MAX_AUTOMATON_STATES ||
  @                ctx_vector.initialized != SECURE_TRUE ||
  @                num_states > MAX_AUTOMATON_STATES ||
  @                num_transition > MAX_AUTOMATON_TRANSITIONS);
  @       assigns ctx_vector.ctx_num;
  @
  @ disjoint behaviors;
  @*/
mbed_error_t automaton_declare_context(__in  const uint8_t num_states,
                                       __in  const uint8_t num_transition,
                                       __in  const automaton_state_t * state_automaton,
                                       __out automaton_ctx_handler_t *ctxh)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /*sanitize */
    if (ctx_vector.initialized != SECURE_TRUE) {
        log_printf("%s: you must initialize first!\n", log_tab[LIBNAME]);
        return MBED_ERROR_INVSTATE;
    }
    if (!ctxh) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (!state_automaton) {
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

    ctx = (automaton_context_t *)&(ctx_vector.contexts[ctx_vector.ctx_num]);

    mutex_lock(&ctx_vector.lock);

    mutex_init(&ctx->state_lock);
    ctx->state_number = num_states;
    ctx->transition_number = num_transition;
    ctx->state_automaton = state_automaton;

    mutex_unlock(&ctx_vector.lock);

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    if (automaton_calculate_context_integrity(ctx, &ctx->crc) != MBED_ERROR_NONE) {
        log_printf("%s %s:unable to calculate CRC!\n", log_tab[LIBNAME], __func__);
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
#endif
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
    ctx->req.state = 0;
    ctx->req.next_state = 0;
    ctx->req.transition = 0;
# if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    ctx->req.crc = 0;
# endif
    ctx->waiting_req = SECURE_FALSE;
#endif
    ctx_vector.ctx_num++;
err:
    return errcode;
}


/*@
  @ ensures ctxh >=ctx_vector.ctx_num
  @   ==> \result == MBED_ERROR_INVPARAM;
  @ ensures !(\valid(state))
  @   ==> \result == MBED_ERROR_INVPARAM;
  @ ensures ctx_vector.initialized != SECURE_TRUE
  @   ==> \result == MBED_ERROR_INVSTATE;
  @
  @ behavior bad_entries:
  @   assumes ctxh >= ctx_vector.ctx_num ||
  @            !(\valid(state)) ||
  @            ctx_vector.initialized != SECURE_TRUE;
  @     assigns \nothing;
  @     ensures \result != MBED_ERROR_NONE;
  @
  @ behavior good_entries:
  @     assumes ctxh < ctx_vector.ctx_num &&
  @            \valid(state) &&
  @            ctx_vector.initialized == SECURE_TRUE;
  @     assigns *state;
  @     ensures \result == MBED_ERROR_NONE;
  @
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
mbed_error_t automaton_get_state(__in  const automaton_ctx_handler_t ctxh,
                                 __out state_id_t                   *state)
{
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
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
    if ((ctx = automaton_get_context(ctxh)) == NULL) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    *state = automaton_convert_state(ctx->state);
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

/*@
  @ ensures ctxh >=ctx_vector.ctx_num
  @   ==> \result == MBED_ERROR_INVPARAM;
  @ ensures ctx_vector.initialized != SECURE_TRUE
  @   ==> \result == MBED_ERROR_INVSTATE;
  @
  @ behavior bad_entries:
  @   assumes ctxh >= ctx_vector.ctx_num ||
  @            ctx_vector.initialized != SECURE_TRUE;
  @     assigns \nothing;
  @     ensures \result != MBED_ERROR_NONE;
  @
  @*/
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
    if ((ctx = automaton_get_context(ctxh)) == NULL) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    if (automaton_state_exists(ctx, new_state) == SECURE_FALSE &&
        !(automaton_state_exists(ctx, new_state) != SECURE_FALSE)) {
        goto err;
    }

    mutex_lock(&ctx->state_lock);
    log_printf("%s: %s set from %d to %d\n", __func__, log_tab[STATE], automaton_convert_secure_state(ctx->state), new_state);
    ctx->state = automaton_convert_state(new_state);
    /* hardening assignation */
    if (ctx->state != automaton_convert_state(new_state) &&
        !(ctx->state == automaton_convert_state(new_state))) {
        errcode = MBED_ERROR_WRERROR;
        goto err;
    }
    mutex_unlock(&ctx->state_lock);
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

/*@
  @ ensures ctxh >=ctx_vector.ctx_num
  @   ==> \result == MBED_ERROR_INVPARAM;
  @ ensures ctx_vector.initialized != SECURE_TRUE
  @   ==> \result == MBED_ERROR_INVSTATE;
  @
  @ behavior bad_entries:
  @   assumes ctxh >= ctx_vector.ctx_num ||
  @            ctx_vector.initialized != SECURE_TRUE;
  @     assigns \nothing;
  @     ensures \result != MBED_ERROR_NONE;
  @
  @*/
mbed_error_t automaton_get_next_state(__in  const automaton_ctx_handler_t     ctxh,
                                      __in  const state_id_t                  current_state,
                                      __in  const transition_id_t             transition,
                                      __out state_id_t                       *newstate)
{
    log_printf("[automaton] %s: getting next state (curr: %d)\n", __func__, current_state);
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;
    automaton_context_t *ctx = NULL;
    uint8_t i = 0;
    /* sanitize */
    if (ctx_vector.initialized != SECURE_TRUE) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if ((ctx = automaton_get_context(ctxh)) == NULL) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    if (automaton_state_exists(ctx, current_state) == SECURE_FALSE &&
        !(automaton_state_exists(ctx, current_state) != SECURE_FALSE)) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (automaton_transition_exists(ctx, transition) == SECURE_FALSE &&
        !(automaton_transition_exists(ctx, transition) != SECURE_FALSE)) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    if (ctx->state_automaton == NULL) {
        log_printf("[automaton] %s: no state automaton!!!\n", __func__);
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }

    log_printf("[automaton] %s: starting search loop on state %d\n", __func__, current_state);

    /* TODO: howto define the special case of unpredictable target state ? */

    /*@  requires \valid(ctx->state_automaton+(0..current_state)); */

    /*@
      @ loop invariant 0 <= i <= ctx->state_automaton[current_state].num_transitions;
      @ loop invariant \forall integer j; 0 <= j < i ==> ctx->state_automaton[current_state].transitions[i].transition_id != transition;
      @ loop assigns i;
      @ loop assigns *newstate;
      @
      @ loop variant ctx->state_automaton[current_state].num_transitions - i;
      @*/
    for (i = 0; i < ctx->state_automaton[current_state].num_transitions; ++i) {
        /*@ requires \valid(&ctx->state_automaton[current_state].transitions[i]); */
        /* hardened if, requiring O0 */
        if (ctx->state_automaton[current_state].transitions[i].transition_id == transition &&
            !(ctx->state_automaton[current_state].transitions[i].transition_id != transition))
        {
            if (ctx->state_automaton[current_state].transitions[i].predictable) {
                *newstate = ctx->state_automaton[current_state].transitions[i].target_state;
                errcode = MBED_ERROR_NONE;
                goto err;
            } else {
                errcode = MBED_ERROR_UNKNOWN;
                goto err;
            }
        }
    }
    errcode = MBED_ERROR_NONE;
err:
    log_printf("[automaton] %s: end of function\n", __func__);
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

/*@
  @ ensures ctxh >=ctx_vector.ctx_num
  @   ==> \result == SECURE_FALSE;
  @ ensures ctx_vector.initialized != SECURE_TRUE
  @   ==> \result == SECURE_FALSE;
  @
  @ behavior bad_entries:
  @   assumes ctxh >= ctx_vector.ctx_num ||
  @            ctx_vector.initialized != SECURE_TRUE;
  @     assigns \nothing;
  @     ensures \result == SECURE_FALSE;
  @
  @ ensures \result == SECURE_TRUE
  @   ==> \exists integer i; 0 <= i < ctx_vector.contexts[ctxh].state_automaton[current_state].num_transitions && ctx_vector.contexts[ctxh].state_automaton[current_state].transitions[i].transition_id == transition;
  @*/
secure_bool_t automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
                                            __in  const state_id_t                  current_state,
                                            __in  const transition_id_t             transition)
{
    secure_bool_t result = SECURE_FALSE;
    automaton_context_t *ctx = NULL;
    uint8_t i = 0;
    /* sanitize */
    /* the first initialization steps are not hardened as a fault on these if will simply generated
     * a memory fault */
    if (ctx_vector.initialized != SECURE_TRUE) {
        log_printf("%s: %s %s!\n", __func__, log_tab[LIBNAME], log_tab[NOT_INIT]);
        goto err;
    }
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
        log_printf("%s: %s %s %s!\n", __func__, log_tab[LIBNAME], log_tab[CONTEXT], log_tab[INVALID]);
        goto err;
    }
    if ((ctx = automaton_get_context(ctxh)) == NULL) {
        log_printf("%s: %s %s %s!\n", __func__, log_tab[LIBNAME], log_tab[CONTEXT], log_tab[INVALID]);
        goto err;
    }
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

    /*@ requires \valid(ctx->state_automaton+(0..current_state)); */

    /*@
      @ loop invariant 0 <= i <= ctx->state_automaton[current_state].num_transitions;
      @ loop invariant \forall integer j; 0 <= j < i ==> ctx->state_automaton[current_state].transitions[i].transition_id != transition;
      @ loop assigns i;
      @ loop assigns result;
      @ loop variant ctx->state_automaton[current_state].num_transitions - i;
      @*/
    for (i = 0; i < ctx->state_automaton[current_state].num_transitions; ++i) {

        /*@ requires \valid(&ctx->state_automaton[current_state].transitions[i]); */
        /* hardened if, requiring O0 */
        if (ctx->state_automaton[current_state].transitions[i].transition_id == transition &&
            !(ctx->state_automaton[current_state].transitions[i].transition_id != transition)) {

            result = SECURE_TRUE;
            goto err;
        }
    }

    log_printf("%s: %s %s %s!\n", __func__, log_tab[LIBNAME], log_tab[TRANSITION], log_tab[NOTFOUND]);
    return result;
err:
    return result;
}


#if defined(__FRAMAC__)

typedef enum {
    FRAMAC_SAMPLE_STATE_0 = 0,
    FRAMAC_SAMPLE_STATE_1,
    FRAMAC_SAMPLE_STATE_2,
} framac_sample_state_t;

typedef enum {
    FRAMAC_SAMPLE_TRANS_0 = 0,
    FRAMAC_SAMPLE_TRANS_1,
    FRAMAC_SAMPLE_TRANS_2,
    FRAMAC_SAMPLE_TRANS_3,
} framac_sample_trans_t;

/*
 * Support for Frama-C testing
 */
int main(void)
{

    /* we fix input data that are .rodata, stored in flash */
    uint8_t num_states = 3;
    uint8_t num_transitions = 4;
    automaton_ctx_handler_t ctxh = Frama_C_interval(0,255);


    /* transitions for state 0 */
    static const transition_spec_t state_0_trans_tab[] = {
            {
              .transition_id = FRAMAC_SAMPLE_TRANS_0,
              .target_state  = FRAMAC_SAMPLE_STATE_1,
              .predictable   = true,
            },
            {
              .transition_id = FRAMAC_SAMPLE_TRANS_1,
              .target_state  = FRAMAC_SAMPLE_STATE_2,
              .predictable   = true,
            }
    };

    /*transitions for state 1 */
    static const transition_spec_t state_1_trans_tab[] = {
            {
              .transition_id = FRAMAC_SAMPLE_TRANS_2,
              .target_state  = FRAMAC_SAMPLE_STATE_2,
              .predictable   = true,
            }
    };

    /*transitions for state 2 */
    static const transition_spec_t state_2_trans_tab[] = {
            {
              .transition_id = FRAMAC_SAMPLE_TRANS_3,
              .target_state  = FRAMAC_SAMPLE_STATE_0,
              .predictable   = true,
            }
    };


    static const automaton_state_t framac_automaton[] = {
        {
          .state = FRAMAC_SAMPLE_STATE_0,
          .num_transitions = 2,
          .transitions = &state_0_trans_tab[0]
        },
        {
          .state = FRAMAC_SAMPLE_STATE_1,
          .num_transitions = 1,
          .transitions = &state_1_trans_tab[0]
        },
        {
          .state = FRAMAC_SAMPLE_STATE_2,
          .num_transitions = 1,
          .transitions = &state_2_trans_tab[0]
        }
    };

    automaton_initialize();
    automaton_declare_context(num_states, num_transitions, &framac_automaton[0], &ctxh);

    /* initial state */
    automaton_set_state(ctxh, 0);

   /* now, everything can be corrupted */

    uint8_t trans_tab[] = {
        FRAMAC_SAMPLE_TRANS_0,
        FRAMAC_SAMPLE_TRANS_2,
        FRAMAC_SAMPLE_TRANS_3,
        FRAMAC_SAMPLE_TRANS_1,
        FRAMAC_SAMPLE_TRANS_3,
    };
    framac_sample_trans_t cur_trans;
    /* imagine we generate any possible invalid values for ctxh */
    //ctxh = Frama_C_interval(0, 255);
    for (uint8_t i = 0; i < sizeof(trans_tab)/sizeof(uint8_t); ++i) {
        cur_trans = trans_tab[i];
        automaton_push_transition_request(ctxh, cur_trans);
        switch(cur_trans) {
            case 0: {
                        automaton_execute_transition_request(ctxh);
                    }
                    break;
            case 1: {
                        automaton_execute_transition_request(ctxh);
                    }
                    break;
            case 2: {
                        automaton_execute_transition_request(ctxh);
                    }
                    break;
            case 3: {
                        automaton_execute_transition_request(ctxh);
                    }
                    break;
            default:
                    break;
        }
        automaton_postcheck_transition_request(ctxh);
    }
}
#endif/*!__FRAMAC__*/
