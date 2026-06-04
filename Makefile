# mysql-community-audit — build the login_audit MySQL 5.7 audit plugin.
#
# Requires a C++ compiler and the MATCHING mysql-community-devel headers.
# Build on a toolchain whose glibc is <= your server's (same OS family),
# so the resulting .so is ABI-compatible with your mysqld.
#
#   make                      # build login_audit.so (+ ABI self-check)
#   make MYSQL_INCDIR=/path   # if headers aren't under /usr/include
#   sudo make install         # copy into the server's @@plugin_dir
#   make clean

CXX          ?= g++
PLUGIN       := login_audit
SRC          := $(PLUGIN).c
SO           := $(PLUGIN).so

# Directory containing <my_global.h> and the <mysql/...> headers.
# The mysql-community-devel package installs them under /usr/include/mysql.
MYSQL_INCDIR ?= /usr/include

CXXFLAGS     ?= -Wall -O2 -fPIC
# -DMYSQL_ABI_CHECK skips plugin.h's optional plugin-service includes (which pull
# server-source-only headers this plugin doesn't use).
CPPFLAGS     += -DMYSQL_DYNAMIC_PLUGIN -DMYSQL_ABI_CHECK \
                -I. -I$(MYSQL_INCDIR) -I$(MYSQL_INCDIR)/mysql
LDFLAGS      += -shared

# Where `make install` copies the plugin (defaults to the live server's value).
PLUGIN_DIR   ?= $(shell mysql -N -e 'SELECT @@plugin_dir' 2>/dev/null)

.PHONY: all verify install clean

all: verify

$(SO): $(SRC)
        $(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $<

# A loadable MySQL plugin MUST export this symbol — fail the build if it doesn't.
verify: $(SO)
        @nm -D $(SO) | grep -q _mysql_plugin_interface_version_ \
          && echo "OK: $(SO) exports the plugin ABI symbols" \
          || { echo "ERROR: $(SO) is not a valid plugin"; exit 1; }

install: $(SO)
        @test -n "$(PLUGIN_DIR)" || { echo "ERROR: set PLUGIN_DIR=/path/to/plugin_dir"; exit 1; }
        install -m 0644 $(SO) "$(PLUGIN_DIR)/$(SO)"
        @echo "Installed -> $(PLUGIN_DIR)/$(SO)"

clean:
        rm -f $(SO)
