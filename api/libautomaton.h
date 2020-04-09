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


#ifndef LIBAUTOMATON_H_
#define LIBAUTOMATON_H_

#include "autoconf.h"
#include "libc/types.h"

/****************************************************************
 * Generic state automaton types  definition
 ***************************************************************/

/*
 * secure boolean, not exactly inverted, with a Hamming distance long enough
 */
typedef enum {
    SECURE_FALSE = 0xacefaecf,
    SECURE_TRUE =  0xca38c3e8
} secure_bool_t;


/*
 *
 */
typedef uint8_t transition_id_t;
typedef uint8_t state_id_t;


typedef struct {
    transition_id_t transition_id;   /*< transition identifier */
    state_id_t      target_state;    /*< target state (when predictable) */
    bool            predictable;      /*< is transition predictable (depends only on current state) */
} transition_spec_t;


typedef struct {
    state_id_t      state;
    transition_spec_t transition[]; /*< this table length is max_transition_per_state length */
} automaton_transition_t;

/* contexts are opaque contents, upper layer get back a handler, corresponding to the
 * cell identifier in the contexts vector. This avoid any direct access to the context data,
 * including the state */
typedef uint8_t automaton_ctx_handler_t;


/****************************************************************
 * Generic state automaton API
 ***************************************************************/

mbed_error_t automaton_declare_context(__in  const uint8_t num_states,
                                       __in  const uint8_t num_transition,
                                       __in  const uint8_t max_transition_per_state,
                                       __in  const automaton_transition_t *const * const state_automaton,
                                       __out automaton_ctx_handler_t *ctxh);

state_id_t automaton_get_state(__in  const automaton_ctx_handler_t ctxh,
                               __out state_id_t                   *state);

mbed_error_t automaton_set_state(const automaton_ctx_handler_t ctxh,
                                 const state_id_t new_state);

mbed_error_t automaton_get_next_state(__in  const automaton_ctx_handler_t     ctxh,
                                      __in  const state_id_t                  current_state,
                                      __in  const transition_id_t             transition,
                                      __out state_id_t                       *newstate);

secure_bool_t automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
                                            __in  const state_id_t                  current_state,
                                            __in  const transition_id_t             transition);


/****************************************************************
 * CFI specific automaton API
 ***************************************************************/

/*
 * push a transition request to the state automaton, by indicating the transition
 * identifier. States are handled by the automaton itself.
 * Pushing the transition request *does not* modify the automaton current state, but
 * only push a transition request flag into the automaton context.
 * This flag is handled by the automaton_execute_transition_request() function.
 *
 * This function is typically called at the begining of the main automaton loop of the
 * application.
 */
mbed_error_t automaton_push_transition_request(const automaton_ctx_handler_t ctxh,
                                               const transition_id_t req);


/*
 * Execute a previously pushed transition request.
 * The transition integrity and conformity to the current automaton state is checked.
 * The state automaton is updated to the target state of the transition if the transition
 * is valid.
 *
 * This function is typically executed in each transition function.
 */
mbed_error_t automaton_execute_transition_request(const automaton_ctx_handler_t ctxh);


/*
 * postcheck that the previous transition has been executed properly. This function is
 * executed *after* the transition function. It is a post-validation check which validate
 * that the previously required transition comes from a valid state to the current state,
 * and clean the previously required transition.
 *
 * This function is typically executed at the end of the main automaton loop of the
 * application.
 */
mbed_error_t automaton_postcheck_transition_request(const automaton_ctx_handler_t ctxh);

#endif/*!LIBAUTOMATON_H_*/
