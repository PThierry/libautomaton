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

#ifndef AUTOMATON_H_
#define AUTOMATON_H_

#include "api/libautomaton.h"
#include "libc/types.h"
#include "libc/stdio.h"

#define AUTOMATON_DEBUG CONFIG_USR_LIB_AUTOMATON_DEBUG

#if AUTOMATON_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif


typedef uint32_t secure_state_id_t;
typedef uint64_t secure_transition_id_t;


#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
typedef struct {
    secure_state_id_t  state;
    secure_state_id_t  next_state;
    transition_id_t    transition;
# if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    uint32_t           crc;
# endif
} automaton_transition_request_t;
#endif


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
#if defined(__FRAMAC__)
    secure_state_id_t state;                      /*< current state */
    uint32_t   state_lock;                /*< state WR access lock */
#else
    volatile secure_state_id_t state;                      /*< current state */
    uint32_t   state_lock;                /*< state WR access lock */
#endif/*!FRAMAC*/
    const automaton_state_t *state_automaton; /*< declared state automaton */

#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK
    uint32_t            crc;
#endif
#if CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
# if defined(__FRAMAC__)
    automaton_transition_request_t    req;
    secure_bool_t           waiting_req;
# else
    volatile automaton_transition_request_t    req;
    volatile secure_bool_t           waiting_req;
# endif/*!FRAMAC*/
#endif
} automaton_context_t;

typedef struct {
# if defined(__FRAMAC__)
    uint32_t            lock;
    uint8_t             ctx_num;
    secure_bool_t       initialized;
#else
    uint32_t            lock;
    volatile uint8_t             ctx_num;
    volatile secure_bool_t       initialized;
#endif/*!FRAMAC*/
    automaton_context_t contexts[CONFIG_USR_LIB_AUTOMATON_MAX_CONTEXT_NUM];
} automaton_ctx_vector_t;


#ifdef CONFIG_USR_LIB_AUTOMATON_CONTROL_FLOW_INTEGRITY
/*
 * This function is made privative in case of CFI use, setters is limited to CFI functions
 * only
 */
mbed_error_t automaton_set_state(const automaton_ctx_handler_t ctxh,
                                 const state_id_t new_state);
#endif



/* automaton locally exported API (internal to libautomaton */

secure_bool_t automaton_ctx_exists(const automaton_ctx_handler_t ctxh);

secure_bool_t automaton_ctx_exists(const automaton_ctx_handler_t ctxh);

secure_bool_t automaton_state_exists(const automaton_context_t * const ctx,
                                     const state_id_t                  state);

secure_bool_t automaton_transition_exists(const automaton_context_t * const ctx,
                                          const transition_id_t             transition);

secure_state_id_t automaton_convert_state(state_id_t state);

secure_transition_id_t automaton_convert_transition(transition_id_t transition);

state_id_t automaton_convert_secure_state(secure_state_id_t state);

transition_id_t automaton_convert_secure_transition(secure_transition_id_t transition);

automaton_context_t *automaton_get_context(const automaton_ctx_handler_t ctxh);

#endif/*!AUTOMATON_H_*/
