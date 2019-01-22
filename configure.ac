AC_INIT([yubiserver], [0.6],
	[nanakos@wired-net.gr], [yubiserver],
	)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
#AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_INIT_AUTOMAKE(yubiserver,0.6)
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_MSG_CHECKING([for SQLITE library])
PKG_CHECK_MODULES([sqlite3], [sqlite3])


AC_CHECK_LIB(mhash,mhash_hmac_init,,AC_MSG_ERROR([Cannot find libmhash]))

AC_CHECK_LIB(ev,ev_io_start,,AC_MSG_ERROR([Cannot find libev]))
#AC_CHECK_LIB(config,config_init,,AC_MSG_ERROR([Cannot find libconfig]))

PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2],,
		       AC_MSG_ERROR([libconfig 1.3.2 or newer not found.])
		            )

AM_PATH_LIBGCRYPT


AC_ARG_WITH(default_sqlite3_db_file,
		[  --with-default-sqlite3-db-file=FILE Specify default sqlite3 database file to use
		         [[/var/lib/yubiserver/yubiserver.sqlite]] ])

if test "x$with_default_sqlite3_db_file" != "x" -a "x$with_default_sqlite3_db_file" != "xyes"; then
	AC_DEFINE_UNQUOTED(SQLITE3_DB_PATH,"$with_default_sqlite3_db_file",[Define the default SQLite3 Database File])
else
	AC_DEFINE_UNQUOTED(SQLITE3_DB_PATH,"yubiserver.sqlite",[Define the default SQLite3 Database File])
fi

AC_ARG_WITH(default_yubiserver_log_file,
		[  --with-default-yubiserver-log-file=FILE Specify default yubiserver log file to use
		         [[/var/log/yubiserver/yubiserver.log]] ])

if test "x$with_default_yubiserver_log_file" != "x" -a "x$with_default_yubiserver_log_file" != "xyes"; then
	AC_DEFINE_UNQUOTED(YUBISERVER_LOG_PATH,"$with_default_yubiserver_log_file",[Define the default yubiserver log file])
else
	AC_DEFINE_UNQUOTED(YUBISERVER_LOG_PATH,"yubiserver.log",[Define the default yubiserver log file])
fi

AC_CONFIG_FILES([
  Makefile
])

AC_OUTPUT
