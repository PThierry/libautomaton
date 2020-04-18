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

#ifndef AUTOMATON_DATA_INTEGRITY_H_
#define AUTOMATON_DATA_INTEGRITY_H_

#include "api/libautomaton.h"
#include "libc/types.h"
#include "libc/stdio.h"
#include "automaton.h"


#if CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK

/*
 * Check automaton context integrity. The context integrity must be previously calculated and store
 * in order to get a valid comparison with an initialized integrity field
 */
secure_bool_t automaton_check_context_integrity(__in const automaton_context_t * const ctx);


/*
 * Calculate context integrity. The context integrity is calculated and returned to the crc variable.
 * This variable must be stored in the context integrity field.
 */
mbed_error_t automaton_calculate_context_integrity(__in  const automaton_context_t * const ctx,
                                                   __out uint32_t                         *crc);

/*
 * Calculate requests integrity. The request integrity is calculated and returned to the crc variable.
 * This variable must be stored in the request integrity field.
 */
mbed_error_t automaton_calculate_request_integrity(__in  volatile const automaton_transition_request_t * const req,
                                                   __out volatile uint32_t                *crc);

/*
 * Check request integrity. The request integrity must be previously calculated and store
 * in order to get a valid comparison with an initialized integrity field
 */
secure_bool_t automaton_check_request_integrity(__in volatile const automaton_transition_request_t * const req);

#endif/*!CONFIG_USR_LIB_AUTOMATON_DATA_INTEGRITY_CHECK*/

#endif/*!AUTOMATON_DATA_INTEGRITY_H_*/
