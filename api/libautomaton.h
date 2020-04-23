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
    state_id_t               state;
    uint8_t                  num_transitions;
    const transition_spec_t *transitions;
} automaton_state_t;

/* contexts are opaque contents, upper layer get back a handler, corresponding to the
 * cell identifier in the contexts vector. This avoid any direct access to the context data,
 * including the state */
typedef uint8_t automaton_ctx_handler_t;


/****************************************************************
 * Generic state automaton API
 ***************************************************************/

/*
 * Initialize the automaton library. First function to call.
 * All other functions of the API will fail while this function is not correctly executed.
 */
mbed_error_t automaton_initialize(void);

/*
 * Declare a new automaton in the libautomaton.
 * An automaton is defined by:
 * - its number of states
 * - its number of transition
 * - the maximum number of transitions per state
 * These three informations define the size and structure of the automaton table formalism
 * - the automaton table, containing each state and associated allowed transition
 * - the automaton handler, set by the function on success
 *
 * \returns MBED_ERROR_NONE if the context register is made properly.
 */
mbed_error_t automaton_declare_context(__in  const uint8_t num_states,
                                       __in  const uint8_t num_transition,
                                       __in  const automaton_state_t * state_automaton,
                                       __out automaton_ctx_handler_t *ctxh);

/*
 * Get the current automaton state for the given automaton handler
 */
state_id_t automaton_get_state(__in  const automaton_ctx_handler_t ctxh,
                               __out state_id_t                   *state);

/*
 * Set a new state for the automaton. Executed by transition request functions.
 * This function is made only if CFI is *disabled*. When using CFI (see below)
 * this function is not needed, as the automaton_execute_transition_request() handles it
 * and in this last case, is only reserved for initial state configuration.
 */
mbed_error_t automaton_set_state(const automaton_ctx_handler_t ctxh,
                                 const state_id_t new_state);

/*
 * get back the next state for the given (state/transition) pair.
 * If the automaton is predictable (the pair always target a well known target state),
 * the new state is written to newstate and the function returns MBED_ERROR_NONE.
 * If not, the functions returns MBED_ERROR_UNKNOWN.
 */
mbed_error_t automaton_get_next_state(__in  const automaton_ctx_handler_t     ctxh,
                                      __in  const state_id_t                  current_state,
                                      __in  const transition_id_t             transition,
                                      __out state_id_t                       *newstate);

/*
 * Check if the pair (state/transition) is valid regarding the automaton identified by its
 * handler. The functions returns SECURE_TRUE or SECURE_FALSE, depending on the result.
 */
secure_bool_t automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
                                            __in  const state_id_t                  current_state,
                                            __in  const transition_id_t             transition);


/****************************************************************
 * CFI specific automaton API
 ***************************************************************/

/*
 * CFI API is an implementation of a control flow integrity mechanism against fault
 * injection and software overflow/corruption. The application can use them in replacement
 * of the previously defined set_state/get_next_state/is_valid_transition.
 *
 * Instead the application can handle a code like this:
 *
 * mbed_error_t exec_trans1(automaton_ctx_handler_t ctxh)
 * {
 *     automaton_execute_transition_request(ctxh);
 *     ... // transition specific code
 * }
 *
 * mbed_error_t execute_automaton(automaton_ctx_hander_t ctxh, transition_id_t trans)
 * {
 *   automaton_push_transition_request(ctxh, trans);
 *   switch (trans) {
 *      case TRANS1:
 *          exec_trans1(ctxh);
 *          break;
 *      case TRANS2:
 *          ...
 *   }
 *   automaton_postcheck_transition_request(ctxh);
 * }
 *
 * This avoid any fault injection on the switch/case code and force multiple verification
 * on the transition, its memory integrity and its validity, making fault injection really
 * harder.
 */

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
