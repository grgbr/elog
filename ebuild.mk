config-in                  := Config.in
config-h                   := elog/config.h

ifeq ($(findstring config,$(MAKECMDGOALS)),)
ifneq ($(CONFIG_ELOG_HAVE_IMPL),y)
$(error Invalid build configuration: no implementation module selected !)
endif
endif

common-cflags              := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

solibs                     := libelog.so
libelog.so-objs             = elog.o
libelog.so-cflags           = $(common-cflags) -DPIC -fpic
libelog.so-ldflags          = $(EXTRA_LDFLAGS) \
                              -shared -Bsymbolic -fpic -Wl,-soname,libelog.so
libelog.so-pkgconf          = libutils

bins                        = $(call kconf_enabled,ELOG_LOGGER,elogger)
elogger-objs                = elogger.o
elogger-cflags              = $(common-cflags)
elogger-ldflags            := $(EXTRA_LDFLAGS) -lelog
elogger-pkgconf            := libutils

bins                       += $(call kconf_enabled,ELOG_MQUEUE_UTIL,elog_mqueue)
elog_mqueue-objs            = elog_mqueue.o
elog_mqueue-cflags          = $(common-cflags)
elog_mqueue-ldflags        := $(EXTRA_LDFLAGS) -lelog
elog_mqueue-pkgconf         = libutils
elog_mqueue-path           := $(SBINDIR)/elog_mqueue

ifeq ($(CONFIG_ELOG_SAMPLE),y)

bins                       += $(call kconf_enabled,ELOG_STDIO,elog_sample_hello)
elog_sample_hello-objs      = sample_hello.o
elog_sample_hello-cflags    = $(common-cflags)
elog_sample_hello-ldflags  := $(EXTRA_LDFLAGS) -lelog

bins                       += $(call kconf_enabled,ELOG_STDIO,elog_sample_std)
elog_sample_std-objs        = sample_std.o
elog_sample_std-cflags      = $(common-cflags)
elog_sample_std-ldflags    := $(EXTRA_LDFLAGS) -lelog

bins                       += $(call kconf_enabled,ELOG_MQUEUE, \
                                     elog_sample_mqueue)
elog_sample_mqueue-objs     = sample_mqueue.o
elog_sample_mqueue-cflags   = $(common-cflags)
elog_sample_mqueue-ldflags := $(EXTRA_LDFLAGS) -lelog
elog_sample_mqueue-pkgconf := libutils

bins                       += $(call kconf_enabled,ELOG_SYSLOG, \
                                     elog_sample_syslog)
elog_sample_syslog-objs     = sample_syslog.o
elog_sample_syslog-cflags   = $(common-cflags)
elog_sample_syslog-ldflags := $(EXTRA_LDFLAGS) -lelog

endif # ($(CONFIG_ELOG_SAMPLE),y)

HEADERDIR                  := $(CURDIR)/include
headers                     = elog/elog.h

define libelog_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libelog
Description: Embedded logging library
Version: %%PKG_VERSION%%
Requires:
Cflags: -I$${includedir}
Libs: -L$${libdir} -lelog
endef

pkgconfigs          := libelog.pc
libelog.pc-tmpl     := libelog_pkgconf_tmpl

################################################################################
# Source code tags generation
################################################################################

tagfiles := $(shell find $(CURDIR) $(HEADERDIR) -type f)
