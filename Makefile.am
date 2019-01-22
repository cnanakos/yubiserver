AUTOMAKE_OPTIONS = gnu
bin_PROGRAMS = yubiserver yubiserver-admin

EXTRA_DIST = yubiserver.sqlite TODO

yubiserver_CFLAGS = -Wall -Os
yubiserver_SOURCES = yubiserver.c yubiserver.h
#yubiserver_LDFLAGS = -lsqlite3 -lgcrypt -lmhash  -lconfig -lm -lev
yubiserver_LDADD = -lsqlite3 -lgcrypt -lmhash  -lconfig -lm -lev
#yubiserver_HEADERS = yubiserver.h
yubiserver_admin_CFLAGS = -Wall  -Os
yubiserver_admin_SOURCES = yubiserver-admin.c yubiserver.h
#yubiserver_admin_LDFLAGS = -lsqlite3 -lconfig -lm 
yubiserver_admin_LDADD = -lsqlite3 -lconfig -lm 
#yubiserver_admin_HEADERS = yubiserver.h
