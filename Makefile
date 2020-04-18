###################################################################
# About the library name and path
###################################################################

# library name, without extension
LIB_NAME ?= libautomaton

# project root directory, relative to app dir
PROJ_FILES = ../../

# library name, with extension
LIB_FULL_NAME = $(LIB_NAME).a

# SDK helper Makefiles inclusion
-include $(PROJ_FILES)/m_config.mk
-include $(PROJ_FILES)/m_generic.mk

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/libs/$(LIB_NAME)

###################################################################
# About the compilation flags
###################################################################

CFLAGS += $(LIBS_CFLAGS)
# we add -O0 to keep secure if and various security add-ons in the C
# code removed by compiler optimizers
CFLAGS += -MMD -MP -O0

#############################################################
# About library sources
#############################################################

SRC_DIR = .
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

OUT_DIRS = $(dir $(OBJ))

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(OBJ)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

##########################################################
# generic targets of all libraries makefiles
##########################################################

.PHONY: app doc

default: all

all: $(APP_BUILD_DIR) lib

doc:
	$(Q)$(MAKE) BUILDDIR=../$(APP_BUILD_DIR)/doc  -C doc html latexpdf

show:
	@echo
	@echo "\tAPP_BUILD_DIR\t=> " $(APP_BUILD_DIR)
	@echo
	@echo "C sources files:"
	@echo "\tSRC_DIR\t\t=> " $(SRC_DIR)
	@echo "\tSRC\t\t=> " $(SRC)
	@echo "\tOBJ\t\t=> " $(OBJ)
	@echo

lib: $(APP_BUILD_DIR)/$(LIB_FULL_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

# lib
$(APP_BUILD_DIR)/$(LIB_FULL_NAME): $(OBJ)
	$(call if_changed,mklib)
	$(call if_changed,ranlib)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)

#####################################################################
# Frama-C
#####################################################################

SESSION:=frama-c-rte-val-wp.session
JOBS:=$(shell nproc)
TIMEOUT:=30

# "-val-warn-undefined-pointer-comparison none" is to deal with the
# checks (\pointer_comparable( - ,  - )) otherwise added by EVA before
# our tests of pointers against NULL. Those are not understood by WP.
# This is not an issue but should be revisited later. --arno
#
# See https://bts.frama-c.com/view.php?id=2206

frama-c:
	frama-c automaton*.c -machdep x86_32 \
	            -warn-left-shift-negative \
	            -warn-right-shift-negative \
	            -warn-signed-downcast \
	            -warn-signed-overflow \
	            -warn-unsigned-downcast \
	            -warn-unsigned-overflow \
				-kernel-msg-key pp \
				-no-frama-c-stdlib \
				-cpp-extra-args="-nostdinc -I../std/api -Iframac" \
		    -rte \
		    -eva \
		    -wp-dynamic \
		    -eva-slevel 1 \
            -slevel-function="automaton_ctx_exists:100, \
                automaton_state_exists:100, \
                automaton_transition_exists:100, \
                automaton_convert_state:100, \
                automaton_convert_transition:100, \
                automaton_convert_secure_state:200, \
                automaton_convert_secure_transition:200, \
                automaton_initialize:200, \
                automaton_declare_context:400, \
                automaton_get_state:100, \
                automaton_set_state:200, \
                automaton_get_next_state:300, \
                automaton_is_valid_transition:300, \
                automaton_push_transition_request:400, \
                automaton_execute_transition_request:400, \
                automaton_postcheck_transition_request:400, \
                automaton_check_context_integrity:200, \
                automaton_calculate_context_integrity:100, \
                automaton_check_request_integrity:200, \
                automaton_calculate_request_integrity:100" \
		    -eva-warn-undefined-pointer-comparison none \
		    -then \
		    -wp \
		    -wp-no-dynamic \
		    -wp-par $(JOBS) \
			-wp-simpl \
			-wp-let \
		    -wp-steps 100000 -pp-annot \
		    -wp-split -wp-literals \
			-wp-model "Typed+ref+int+float" \
			-wp-timeout $(TIMEOUT) -save $(SESSION) \
	    	-wp-prover alt-ergo,cvc4,cvc4-ce,z3,z3-ce,z3-nobv \
	        -then -report

frama-c-gui:
	frama-c-gui -load $(SESSION)


