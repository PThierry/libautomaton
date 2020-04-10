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
TIMEOUT:=15

# "-val-warn-undefined-pointer-comparison none" is to deal with the
# checks (\pointer_comparable( - ,  - )) otherwise added by EVA before
# our tests of pointers against NULL. Those are not understood by WP.
# This is not an issue but should be revisited later. --arno
#
# See https://bts.frama-c.com/view.php?id=2206

frama-c:
	frama-c-gui automaton*.c -machdep x86_32 \
	            -warn-left-shift-negative \
	            -warn-right-shift-negative \
	            -warn-signed-downcast \
	            -warn-signed-overflow \
	            -warn-unsigned-downcast \
	            -warn-unsigned-overflow \
				-kernel-msg-key pp \
				-no-frama-c-stdlib \
				-cpp-extra-args="-nostdinc -I../std/api -I../firmware/api -I../../include/generated -I../../drivers/socs/stm32f439/flash/api" \
		    -rte \
		    -eva \
		    -wp-dynamic \
		    -eva-slevel 1 \
		    -eva-warn-undefined-pointer-comparison none \
		    -then \
		    -wp \
		    -wp-dynamic \
		    -wp-par $(JOBS) \
		    -wp-steps 100000 -wp-depth 100000 -pp-annot \
		    -wp-split -wp-literals \
			-wp-timeout $(TIMEOUT) -save $(SESSION)

frama-c-gui:
	frama-c-gui -load $(SESSION)


