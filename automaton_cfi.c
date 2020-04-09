#include "automaton_cfi.h"
#include "automaton.h"
#include "string.h"


/* INFO: CFI on FSM can be done, here, only on predictable state automaton (i.e. an
 * automaton for which all (state,transition) pair generate a single, unique target
 * state.
 * If the target state depends on an external entity (a variable for exemple), the
 * CFI can't be correctly executed because it can't be properly post-checked.
 */
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
/*
 * Push a transition request to the automaton context
 */
mbed_error_t automaton_push_transition_request(__in const automaton_ctx_handler_t ctxh,
                                               __in const transition_id_t req)
{
    /* errcode, default fail */
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    /* the first initialization steps are not hardened as a fault on these if will simply generated
     * a memory fault */
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (ctx->waiting_req == SECURE_TRUE &&
        !(ctx->waiting_req != SECURE_TRUE)) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    /* in requests, we use secure states, not basic states identifiers, making requests harder to
     * corrupt */
    state_id_t unsecure_state;
    if (automaton_get_state(ctxh, &unsecure_state) != MBED_ERROR_NONE) {
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    ctx->req.state = automaton_convert_state(unsecure_state);
    if (automaton_get_next_state(ctxh, automaton_convert_secure_state(ctx->req.state), req, &unsecure_state) != MBED_ERROR_NONE) {
        log_printf("[AUTOMATON] unable to execute CFI on unpredictable state automaton !\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    ctx->req.next_state = automaton_convert_state(unsecure_state);

    ctx->req.transition = req;
#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    if (automaton_calculate_request_integrity(&ctx->req, &ctx->req.crc) != MBED_ERROR_NONE) {
        log_printf("[automaton] %s:unable to calculate request CRC!\n", __func__);
        errcode = MBED_ERROR_WRERROR;
        goto err;
    }
#endif
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

mbed_error_t automaton_execute_transition_request(__in const automaton_ctx_handler_t ctxh)
{
    /* errcode, default fail */
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    /* the first initialization steps are not hardened as a fault on these if will simply generated
     * a memory fault */
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (ctx->waiting_req == SECURE_FALSE &&
        !(ctx->waiting_req != SECURE_FALSE)) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    if (automaton_check_request_integrity(&ctx->req) != SECURE_TRUE &&
        !(automaton_check_request_integrity(&ctx->req) == SECURE_TRUE)) {
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
#endif
    /* input data validated. Check that transition is valid from the automaton point of
     * vue */
    secure_state_id_t state = ctx->req.state;
    secure_state_id_t next_state = ctx->req.next_state;
    transition_id_t transition = ctx->req.transition;

    secure_state_id_t current_state = ctx->state;
    if (state != current_state) {
        log_printf("[automaton] %s:transition from invalid starting state: %x\n", __func__, state);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    /*secure if */
    if (automaton_is_valid_transition(ctxh, state, transition) != SECURE_TRUE &&
        !(automaton_is_valid_transition(ctxh, state, transition) == SECURE_TRUE)) {
        log_printf("[automaton] %s:transition invalid in current state: %x\n", __func__, transition);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    state_id_t next_state_unsecure;
    if (automaton_get_next_state(ctxh, automaton_convert_secure_state(ctx->req.state), ctx->req.transition, &(next_state_unsecure)) != MBED_ERROR_NONE) {
        log_printf("[automaton] unable to execute CFI on unpredictable state automaton !\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (next_state_unsecure != automaton_convert_secure_state(next_state)) {
        log_printf("[automaton] invalid target state %x!\n", __func__, next_state);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    /* we can set the new state now */
    if (automaton_set_state(ctxh, next_state_unsecure) != MBED_ERROR_NONE) {
        errcode = MBED_ERROR_WRERROR;
        goto err;
    }
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

mbed_error_t automaton_postcheck_transition_request(__in const automaton_ctx_handler_t ctxh)
{
    /* errcode, default fail */
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
    automaton_context_t *ctx = NULL;
    /* sanitize */
    /* the first initialization steps are not hardened as a fault on these if will simply generated
     * a memory fault */
    if (automaton_ctx_exists(ctxh) != SECURE_TRUE) {
        goto err;
    }
    ctx = automaton_get_context(ctxh);
    if (ctx->waiting_req == SECURE_FALSE &&
        !(ctx->waiting_req != SECURE_FALSE)) {
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    if (automaton_check_request_integrity(&ctx->req) != SECURE_TRUE &&
        !(automaton_check_request_integrity(&ctx->req) == SECURE_TRUE)) {
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
#endif
    /* get back current context */
    secure_state_id_t next_state = ctx->req.next_state;

    /* make sure that previous transition is a valid transition to the current context
     *  1. transition is valid
     *  2. transition targets current state (not another one)
     */
    secure_state_id_t current_state = ctx->state;
    if (next_state != current_state) {
        log_printf("[automaton] %s:posthook: transition to different target state: %x\n", __func__, state);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    state_id_t next_state_unsecure;
    if (automaton_get_next_state(ctxh, automaton_convert_secure_state(ctx->req.state), ctx->req.transition, &(next_state_unsecure)) != MBED_ERROR_NONE) {
        log_printf("[automaton] unable to execute CFI on unpredictable state automaton !\n");
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }
    if (next_state_unsecure != automaton_convert_secure_state(next_state)) {
        log_printf("[automaton] invalid target state for previous transition %x!\n", __func__, next_state);
        errcode = MBED_ERROR_INVSTATE;
        goto err;
    }

    /* cleanup previous transition */
    memset((void*)&ctx->req, 0x0, sizeof(automaton_transition_request_t));
    ctx->waiting_req = SECURE_FALSE;
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}
#endif
