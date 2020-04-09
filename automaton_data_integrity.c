#include "automaton_data_integrity.h"
#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
#include "libfw.h"
#endif


#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
secure_bool_t automaton_check_context_integrity(__in const automaton_context_t * const ctx)
{
    secure_bool_t result = SECURE_FALSE;
    /* sanitize */
    if (ctx == NULL) {
        goto err;
    }
    uint32_t crc_ctx = 0xffffffff;
    crc_ctx = crc32((unsigned char*)&ctx->state_number, sizeof(num_states), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->transition_number, sizeof(num_transition), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->max_transitions_per_state, sizeof(max_transitions_per_state), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->state_automaton, sizeof(state_automaton), crc_ctx);
    /*hardened if */
    if (ctx->crc != crc_ctx &&
        !(ctx->crc == crc_ctx)) {
        log_printf("[automaton] %s:invalid data integrit     y check: crc32: %x != %x\n", __func__, crc, crc_ctx);
        goto err;
    }

    result = SECURE_TRUE;
err:
    return result;
}


mbed_error_t automaton_calculate_context_integrity(__in  const automaton_context_t * const ctx,
                                                   __out uint32_t                         *crc)
{
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
    /* sanitize */
    if (ctx == NULL || crc == NULL) {
        goto err;
    }

    uint32_t crc_ctx = 0xffffffff;
    crc_ctx = crc32((unsigned char*)&ctx->state_number, sizeof(num_states), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->transition_number, sizeof(num_transition), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->max_transitions_per_state, sizeof(max_transitions_per_state), crc_ctx);
    crc_ctx = crc32((unsigned char*)&ctx->state_automaton, sizeof(state_automaton), crc_ctx);

    *crc = crc_ctx;
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}


secure_bool_t automaton_check_request_integrity(__in const automaton_transition_request_t * const req)
{
    secure_bool_t result = SECURE_FALSE;
    /* sanitize */
    if (req == NULL) {
        goto err;
    }

    /* check current context integrity */
    uint32_t crc = 0xffffffff;
    crc = crc32((unsigned char*)&(req->state), sizeof(secure_state_id_t), crc);
    crc = crc32((unsigned char*)&(req->next_state), sizeof(secure_state_id_t), crc);
    crc = crc32((unsigned char*)&(req->transition), sizeof(transition_id_t), crc);
    if (req->crc != crc &&
        !(req->crc == crc)) {
        log_printf("[automaton] %s:invalid request integrity check: crc32: %x != %x\n", __func__, crc, req->crc);
        goto err;
    }
    result = SECURE_TRUE;
err:
    return result;
}


mbed_error_t automaton_calculate_request_integrity(__in  const automaton_transition_request_t * const req,
                                                   __out uint32_t                         *crc)
{
    mbed_error_t errcode = MBED_ERROR_INVPARAM;
    /* sanitize */
    if (req == NULL || crc == NULL) {
        goto err;
    }

    /* check current context integrity */
    uint32_t crc_req = 0xffffffff;
    crc = crc32((unsigned char*)&(req->state), sizeof(secure_state_id_t), crc_req);
    crc = crc32((unsigned char*)&(req->next_state), sizeof(secure_state_id_t), crc_req);
    crc = crc32((unsigned char*)&(req->transition), sizeof(transition_id_t), crc_req);

    *crc = crc_req;
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

#endif


