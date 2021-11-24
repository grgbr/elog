config-in                  := Config.in
config-h                   := elog/config.h

common-cflags              := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

solibs                     := libelog.so
libelog.so-objs             = elog.o
libelog.so-cflags           = $(common-cflags) -DPIC -fpic
libelog.so-ldflags          = $(EXTRA_LDFLAGS) \
                              -shared -fpic -Wl,-soname,libelog.so
libelog.so-pkgconf          = libutils

bins                        = $(call kconf_enabled,ELOG_LOGGER,elogger)
elogger-objs                = elogger.o
elogger-cflags              = $(common-cflags)
elogger-ldflags            := $(EXTRA_LDFLAGS) -lelog
elogger-pkgconf            := libutils

ifeq ($(CONFIG_ELOG_SAMPLE),y)

bins                       += $(call kconf_enabled,ELOG_STDIO,elog_sample_hello)
elog_sample_hello-objs      = sample_hello.o
elog_sample_hello-cflags    = $(common-cflags)
elog_sample_hello-ldflags  := $(EXTRA_LDFLAGS) -lelog

bins                       += $(call kconf_enabled,ELOG_STDIO,elog_sample_std)
elog_sample_std-objs        = sample_std.o
elog_sample_std-cflags      = $(common-cflags)
elog_sample_std-ldflags    := $(EXTRA_LDFLAGS) -lelog

bins                       += $(call kconf_enabled,ELOG_FILE,elog_sample_file)
elog_sample_file-objs       = sample_file.o
elog_sample_file-cflags     = $(common-cflags)
elog_sample_file-ldflags   := $(EXTRA_LDFLAGS) -lelog

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
