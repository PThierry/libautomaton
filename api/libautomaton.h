
#include "autoconf.h"
#include "libc/types.h"

/****************************************************************
 * Generic state automaton types  definition
 ***************************************************************/


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

bool automaton_is_valid_transition(__in  const automaton_ctx_handler_t     ctxh,
                                   __in  const state_id_t                  current_state,
                                   __in  const transition_id_t             transition);
