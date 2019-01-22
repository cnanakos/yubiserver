/* Copyright (c) 2011 - 2014 Nanakos Chrysostomos <nanakos@wired-net.gr>
   Simple and lightweight Yubikey OTP-OATH/HOTP Validation Server

   yubiserver-admin is placed under the GNU General Public License, version 2
   or later.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gcrypt.h>
#include <sqlite3.h>
#include <time.h>
#include <sys/timeb.h>
#include <getopt.h>
#include <math.h>
#include <mhash.h>

#include "yubiserver.h"

#define YUBIKEY 0
#define OATH    1
#define API     2

static int yubikey_table;
static int oath_table;
static int api_table;
static int ext_db;
static int Argc;
static char **Argv;


static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static int mod_table[] = {0, 2, 1};

static char *base64_encode(const unsigned char *data, size_t input_length,
                           size_t output_length)
{
    int i,j;
    output_length = (size_t) (4.0 * ceil((double) input_length / 3.0));
    char *encoded_data = calloc(1, output_length);
    if (encoded_data == NULL) {
        return NULL;
    }
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[output_length - 1 - i] = '=';
    }
    return encoded_data;
}

static void print_table(char *table, int id)
{
    int retval, rows = 0;
    char *query = NULL;
    sqlite3 *handle;
    sqlite3_stmt *stmt;

    if (id == YUBIKEY || id == OATH) {
        query = calloc(1, QUERY_SIZE);
        snprintf(query, QUERY_SIZE,
                 "SELECT nickname,publicname,active FROM %s",
                 table);
    } else if (id == API) {
        query = calloc(1, QUERY_SIZE);
        snprintf(query, QUERY_SIZE,
                 "SELECT nickname,id FROM %s",
                 table);
    }
    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval) {
        fprintf(stderr, "Database connection failed");
        exit(2);
    }

    if (query != NULL) {
        retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);
    }

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare failed");
        exit(2);
    }

    while (true) {
        retval = sqlite3_step(stmt);

        switch (retval) {
        case SQLITE_ROW:
            if(id == YUBIKEY || id == OATH) {
                if (!rows) {
                    printf("%-20s %-20s %-20s\n",
                           "[Username]", "[Public Token ID]", "Active");
                }
                printf("%-20s %-20s %-20s\n", sqlite3_column_text(stmt, 0),
                                              sqlite3_column_text(stmt, 1),
                                              sqlite3_column_text(stmt, 2));
                rows++;
            } else if (id == API) {
                if (!rows) {
                    printf("%-20s %-20s\n","[Username]","[API ID]");
                }
                printf("%-20s %-20s\n", sqlite3_column_text(stmt, 0),
                                        sqlite3_column_text(stmt,1));
                rows++;
            }
            break;
        case SQLITE_DONE:
            break;
        default:
            fprintf(stderr, "Database error encountered");
            break;
        }
        if (retval != SQLITE_ROW) {
            break;
        }
    }
    sqlite3_close(handle);
    free(query);

    if (!rows) {
        printf("No keys in database.\n");
    }
    printf("Total keys in database: %d\n", rows);
    exit(0);
}

static int finduser(char *table, char *user, sqlite3 *handle)
{
    int retval;
    char *query = NULL;
    sqlite3_stmt *stmt;

    query = calloc(1, QUERY_SIZE);
    snprintf(query,
             QUERY_SIZE,
             "SELECT * FROM %s WHERE nickname='%s'",
             table,
             user);

    retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare failed");
        sqlite3_close(handle);
        free(query);
        exit(2);
    }
    retval = sqlite3_step(stmt);

    switch (retval) {
    case SQLITE_ROW:
        retval = 0;
        break;
    case SQLITE_DONE:
        retval = -1;
        break;
    default:
        break;
    }

    free(query);
    return retval;
}

static void userenable(char *table, char *user)
{
    int retval;
    char *query = NULL;
    sqlite3 *handle;
    sqlite3_stmt *stmt;

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval) {
        fprintf(stderr, "DB connection failed");
        exit(2);
    }

    if (finduser(table, user, handle) < 0) {
        fprintf(stderr, "User '%s' does not exist\n", user);
        exit(2);
    }

    query = calloc(1, QUERY_SIZE);
    snprintf(query,
             QUERY_SIZE,
             "SELECT * FROM %s WHERE nickname = '%s' AND active = '1'",
             table,
             user);

    retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare error\n");
        goto out;
    }
    retval = sqlite3_step(stmt);

    switch (retval) {
    case SQLITE_ROW:
        fprintf(stdout, "User '%s' is already enabled\n", user);
        break;
    case SQLITE_DONE:
        fprintf(stdout, "Trying to enable user '%s'\n", user);
        snprintf(query,
                 QUERY_SIZE,
                 "UPDATE %s SET active = '1' WHERE "
                 "nickname = '%s'",
                 table,
                 user);
        retval = sqlite3_exec(handle, query, 0, 0, 0);
        if (retval) {
            fprintf(stderr, "Updating DB data failed\n");
            goto out;
        }
        fprintf(stdout, "User '%s' enabled\n", user);
        break;
    default:
        fprintf(stderr, "DB error encountered\n");
        break;
    }

out:
    sqlite3_close(handle);
    free(query);
    exit(0);
}

static void userdisable(char *table, char *user)
{
    int retval;
    char *query = NULL;
    sqlite3 *handle;
    sqlite3_stmt *stmt;

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval) {
        fprintf(stderr, "DB connection failed");
        exit(2);
    }

    if (finduser(table, user, handle) < 0) {
        fprintf(stderr, "User '%s' does not exist\n", user);
        exit(2);
    }

    query = calloc(1, QUERY_SIZE);

    snprintf(query,
             QUERY_SIZE,
             "SELECT * FROM %s WHERE nickname = '%s' AND active = '0'",
             table,
             user);

    retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare error\n");
        goto out;
    }
    retval = sqlite3_step(stmt);

    switch (retval) {
    case SQLITE_ROW:
        fprintf(stdout, "User '%s' is already disable\n", user);
        break;
    case SQLITE_DONE:
        fprintf(stdout, "Trying to disable user '%s'\n", user);
        snprintf(query,
                 QUERY_SIZE,
                 "UPDATE %s SET active = '0' WHERE "
                 "nickname = '%s'",
                 table,
                 user);
        retval = sqlite3_exec(handle, query, 0, 0, 0);
        if (retval) {
            fprintf(stderr, "Failed to disable user\n");
            goto out;
        }
        fprintf(stdout, "User '%s' disabled\n", user);
        break;
    default:
        fprintf(stderr, "DB error encountered\n");
        break;
    }

out:
    sqlite3_close(handle);
    free(query);
    exit(0);

}

static void userdelete(char *table, char *user)
{
    int retval;
    char *query = NULL;
    sqlite3 *handle;

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval) {
        fprintf(stderr, "DB connection failed");
        exit(2);
    }

    if (finduser(table, user, handle) < 0) {
        fprintf(stderr, "User '%s' does not exist\n", user);
        exit(2);
    }

    query = calloc(1, QUERY_SIZE);

    snprintf(query,
             QUERY_SIZE,
             "DELETE FROM %s WHERE nickname = '%s'",
             table,
             user);
    retval = sqlite3_exec(handle, query, 0, 0, 0);

    if (retval) {
        fprintf(stderr, "Failed to delete user '%s'\n", user);
        goto out;
    }

    fprintf(stdout, "User '%s' deleted\n", user);

out:
    sqlite3_close(handle);
    free(query);
    exit(0);
}

static int find_nextid(char *table, sqlite3 *handle)
{
    int retval;
    char *query = NULL;
    sqlite3_stmt *stmt;

    query = calloc(1, QUERY_SIZE);
    snprintf(query,
             QUERY_SIZE,
             "SELECT id FROM %s ORDER BY id DESC LIMIT 1",
             table);

    retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare failed");
        sqlite3_close(handle);
        free(query);
        exit(2);
    }
    retval = sqlite3_step(stmt);

    switch (retval) {
    case SQLITE_ROW:
        retval = atoi((char *)sqlite3_column_text(stmt, 0)) + 1;
        break;
    case SQLITE_DONE:
        retval = 1;
        break;
    default:
        fprintf(stderr, "DB error encountered\n");
        exit(2);
    }

    free(query);
    return retval;
}

static int finduser_public(char *table, char *user, char *pname,
                           sqlite3 *handle)
{
    int retval;
    char *query = NULL;
    sqlite3_stmt *stmt;

    query = calloc(1, QUERY_SIZE);
    snprintf(query,
             QUERY_SIZE,
             "SELECT * FROM %s WHERE nickname='%s' OR publicname='%s'",
             table,
             user,
             pname);

    retval = sqlite3_prepare_v2(handle, query, -1, &stmt, 0);

    if (retval) {
        fprintf(stderr, "SQLite3: Query prepare failed");
        sqlite3_close(handle);
        free(query);
        exit(2);
    }
    retval = sqlite3_step(stmt);

    switch (retval) {
    case SQLITE_ROW:
        retval = 0;
        break;
    case SQLITE_DONE:
        retval = -1;
        break;
    default:
        fprintf(stderr, "DB error encountered\n");
        exit(2);
    }

    free(query);
    return retval;

}

static void useradd_yubikey(char *table, char *user)
{
    int retval;
    char *query = NULL;
    char *cdatetime = NULL;
    char *cdatetime_tmp = NULL;
    sqlite3 *handle;
    time_t t;
    struct tm *tmp;
    struct timeb tp;

    if (!ext_db && (Argc != 7 || (strlen(user) > 16 || strlen(Argv[4]) != 12 ||
                    strlen(Argv[5]) != 12 ||
                    strlen(Argv[6]) != 32))) {
        goto err_exit;

    } else if (ext_db && (Argc != 9 || (strlen(user) > 16 ||
                          strlen(Argv[6]) != 12 ||
                          strlen(Argv[7]) != 12 ||
                          strlen(Argv[8]) != 32))) {
        goto err_exit;
    }

    retval = sqlite3_open(sqlite3_dbpath, &handle);
    if (retval) {
        fprintf(stderr, "Database connection failed\n");
        exit(2);
    }

    if (!finduser_public(table, user, ext_db ? Argv[6] : Argv[4], handle)) {
        fprintf(stderr, "Username or public key already exist's."
                        " Delete it before trying to add the "
                        "same key.\n");
        sqlite3_close(handle);
        exit(0);
    }

    t = time(NULL);
    tmp = localtime(&t);
    ftime(&tp);
    cdatetime = calloc(1, 25);
    cdatetime_tmp = calloc(1, 20);
    strftime(cdatetime_tmp, 20, "%Y-%m-%dT%H:%M:%S", tmp);
    snprintf(cdatetime, 25, "%s.%.3dZ", cdatetime_tmp, tp.millitm);

    query = calloc(1, QUERY_SIZE * 2);
    snprintf(query,
             QUERY_SIZE * 2,
             "INSERT INTO %s "
             "VALUES('%s','%s','%s','%s','%s',1,1,1)",
             table,
             user,
             ext_db ? Argv[6]: Argv[4],
             cdatetime,
             ext_db ? Argv[7]: Argv[5],
             ext_db ? Argv[8]: Argv[6]);
    free(cdatetime);
    free(cdatetime_tmp);

    retval = sqlite3_exec(handle, query, 0, 0, 0);
    if (retval) {
        fprintf(stderr, "Failed to add user '%s'", user);
        goto out;
    }
    fprintf(stdout, "Add user '%s' to database\n", user);

out:
    free(query);
    sqlite3_close(handle);
    exit(0);
err_exit:
    fprintf(stderr, "Parameters are not correct. Please try again.\n"
                    "Username should not exceed 16 characters.\n"
                    "Public token ID must be 12 characters long.\n"
                    "Secret token ID must be 12 characters long.\n"
                    "AES key must be 32 characters long.\n");
    exit(2);

}

static void useradd_oath(char *table, char *user)
{
    int retval;
    char *query = NULL;
    char *cdatetime = NULL;
    char *cdatetime_tmp = NULL;
    sqlite3 *handle;
    time_t t;
    struct tm *tmp;
    struct timeb tp;

    if (!ext_db && (Argc != 6 || (strlen(user) > 16 || strlen(Argv[4]) != 12 ||
                    strlen(Argv[5]) != 40))) {
        goto err_exit;

    } else if (ext_db && (Argc != 8 || (strlen(user) > 16 ||
                          strlen(Argv[6]) != 12 ||
                          strlen(Argv[7]) != 40))) {
        goto err_exit;
    }

    retval = sqlite3_open(sqlite3_dbpath, &handle);
    if (retval) {
        fprintf(stderr, "Database connection failed\n");
        exit(2);
    }

    if (!finduser_public(table, user, ext_db ? Argv[6] : Argv[4], handle)) {
        fprintf(stderr, "Username or public key already exist's."
                        " Delete it before trying to add the "
                        "same key.\n");
        sqlite3_close(handle);
        exit(0);
    }

    t = time(NULL);
    tmp = localtime(&t);
    ftime(&tp);
    cdatetime = calloc(1, 25 + 1);
    cdatetime_tmp = calloc(1, 20 + 1);
    strftime(cdatetime_tmp, 20, "%Y-%m-%dT%H:%M:%S", tmp);
    snprintf(cdatetime, 25, "%s.%.3dZ", cdatetime_tmp, tp.millitm);

    query = calloc(1, QUERY_SIZE * 2);
    snprintf(query,
            QUERY_SIZE * 2,
            "INSERT INTO %s "
            "VALUES('%s','%s','%s','%s',1,1)",
            table,
            user,
            ext_db ? Argv[6]: Argv[4],
            cdatetime,
            ext_db ? Argv[7]: Argv[5]);
    free(cdatetime);
    free(cdatetime_tmp);

    retval = sqlite3_exec(handle, query, 0, 0, 0);
    if (retval) {
        fprintf(stderr, "Failed to add user '%s'", user);
        goto out;
    }
    fprintf(stdout, "Add user '%s' to database\n", user);

out:
    free(query);
    sqlite3_close(handle);
    exit(0);
err_exit:
     fprintf(stderr, "Parameters are not correct. Please try again.\n"
                     "Username should not exceed 16 characters.\n"
                     "Public token ID must be 12 characters long.\n"
                     "Secret token ID must be 40 characters long.\n");
    exit(2);
}

static void useradd_api(char *table, char *user)
{
    int retval, nextid;
    char *query = NULL;
    char *key = NULL;
    sqlite3 *handle;

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval) {
        fprintf(stderr, "DB connection failed");
        exit(2);
    }

    if (!finduser(table, user, handle)) {
        fprintf(stderr, "API key for user '%s' already exist's."
                        "Try removing it first or use another name.\n", user);
        exit(2);
    }

    nextid = find_nextid(table, handle);

    if (!ext_db && Argc != 5) {
        goto err_exit;
    } else if (ext_db && Argc != 7){
        goto err_exit;
    }

    if (!ext_db && (strlen(Argv[4]) != 20)) {
        goto err_exit2;
    } else if (ext_db && (strlen(Argv[6]) != 20)) {
        goto err_exit2;
    }

    query = calloc(1, QUERY_SIZE);
    snprintf(query,
             QUERY_SIZE,
             "INSERT INTO apikeys VALUES ('%s','%s','%d')",
             user,
             ext_db ? Argv[6] : Argv[4],
             nextid);

    retval = sqlite3_exec(handle, query, 0, 0, 0);

    if (retval) {
        fprintf(stderr, "Trying to add new API key for '%s' failed\n", user);
        goto out;
    }

    key = ext_db ? Argv[6] : Argv[4];
    fprintf(stdout, "New API key for '%s': %s\n", user,
                    base64_encode((unsigned char *)key,
                    20, 20));
    fprintf(stdout, "You API key ID is: %d\n", nextid);

out:
    sqlite3_close(handle);
    free(query);
    exit(0);
err_exit:
    fprintf(stderr, "Please provide an API key\n");
    sqlite3_close(handle);
    exit(2);
err_exit2:
    fprintf(stderr, "API key must be 20 characters long\n");
    sqlite3_close(handle);
    exit(2);
}

static void db_ops_yubikey(char *table, char *user, int operation)
{
    switch (operation) {
    case ENABLE_USER:
        userenable(table, user);
        break;
    case DISABLE_USER:
        userdisable(table, user);
        break;
    case DELETE_USER:
        userdelete(table, user);
        break;
    case ADD_USER:
        useradd_yubikey(table, user);
        break;
    default:
        break;
    }
}

static void db_ops_oath(char *table, char *user, int operation)
{
    switch (operation) {
    case ENABLE_USER:
        userenable(table, user);
        break;
    case DISABLE_USER:
        userdisable(table, user);
        break;
    case DELETE_USER:
        userdelete(table, user);
        break;
    case ADD_USER:
        useradd_oath(table, user);
        break;
    default:
        break;
    }
}

static void db_ops_api(char *table, char *user, int operation)
{
    switch (operation) {
    case ENABLE_USER:
    case DISABLE_USER:
        fprintf(stderr, "You cannot enable/disable '%s' user in "
                        "API table\n", user);
        exit(0);
    case DELETE_USER:
        userdelete(table, user);
        break;
    case ADD_USER:
        useradd_api(table, user);
        break;
    default:
        break;
    }
}

static void show_table()
{
    if (yubikey_table && !oath_table && !api_table) {
        print_table("yubikeys", YUBIKEY);
    } else if (!yubikey_table && oath_table && !api_table) {
        print_table("oathtokens", OATH);
    } else if (!yubikey_table && !oath_table && api_table) {
        print_table("apikeys", API);
    } else {
        printf("Please choose a table to list.\n");
    }
}

static void user_ops(char *user, int operation)
{
    if (yubikey_table && !oath_table && !api_table) {
        db_ops_yubikey("yubikeys", user, operation);
    } else if (!yubikey_table && oath_table && !api_table) {
        db_ops_oath("oathtokens", user, operation);
    } else if (!yubikey_table && !oath_table && api_table) {
        db_ops_api("apikeys", user, operation);
    } else {
        printf("Please choose a table first.\n");
        exit(2);
    }
}

static void usage()
{
    fprintf(stderr, "yubiserve-admin Yubikey Database Management Tool\n"
       "Version " VERSION_
       ". Written and copyrights by Chrysostomos Nanakos.\n"
       "THIS SOFTWARE COMES WITH ABSOLUTELY NO WARRANTY! "
       "USE AT YOUR OWN RISK!\n"
       "\nUsage: yubiserver-admin "
       "[[-b FILE]] [table] [options] [[attributes]] \n\n"
       "Options supported:\n"
       "   --version or -V			Print version information\n"
       "   --help or -h				Print this help screen\n"
       "   --database or -b			Use this SQLite3 database file (optional)\n"
       "   --yubikey or -y			Choose Yubikey Token table\n"
       "   --oath or -o				Choose OATH Token table\n"
       "   --api or -p				Choose API Key table\n"
       "   --add N [P S [A]] or -a N [P S [A]]  "
       "Add Yubikey OTP & HOTP/OATH token or API Key 'N' user\n"
       "					where N is the username, P the Public Token ID,\n"
       "					S the Secret ID and A the AES key\n"
       "					N must be 16 characters max,P must be 12 characters\n"
       "					for Yubikey OTP and 12 characters max for HOTP/OATH\n"
       "					S must be 12 characters for Yubikey OTP "
       "and 40 for HOTP/OATH\n"
       "					and AES key must be 32 characters\n"
       "					Adding a user to API keys requires a username\n"
       "					and a API Key 20 characters long\n"
       "   --delete N or -x N			Delete Yubikey OTP, HOTP/OATH token "
       "or API Key 'N' user\n"
       "   --enable N or -e N			Enable Yubikey OTP, HOTP/OATH token "
       "'N' user\n"
       "   --disable N or -d N			Disable Yubikey OTP, HOTP/OATH token "
       "'N' user\n"
       "   --list or -l				List Yubikey OTP, HOTP/OATH token or API "
       "key\n"
       "This version of yubiserver-admin has been configured with '"
       SQLITE3_DB_PATH "' as its default\n"
       "SQLite3 database file.\n");
}

int main(int argc, char **argv)
{

    int option_index = 0, c;
    struct option long_options[] = {
        /*Takes no parameters */
        {"version", 0, 0, 'V'},
        {"help", 0, 0, 'h'},
        {"list", 0, 0, 'l'},
        {"yubikey", 0, 0, 'y'},
        {"oath", 0, 0, 'o'},
        {"api", 0, 0, 'p'},

        /* Takes parameters */
        {"add", 1, 0, 'a'},
        {"delete", 1, 0, 'x'},
        {"enable", 1, 0, 'e'},
        {"disable", 1, 0, 'd'},
        {"database", 1, 0, 'b'},
        {0, 0, 0}
    };

    if (argc < 2) {
        usage();
        exit(0);
    }

    while ((c = getopt_long(argc, argv, "Vhlyopa:x:e:d:b:", long_options,
                            &option_index)) != -1) {
        switch (c) {
        case 'V':
            printf("yubiserver-admin version " VERSION_ ". Copyright (C) "
                   "2011 - 2014 Chrysostomos Nanakos.\n"
                   "This program is free software; you can redistribute it "
                   "and/or modify\n"
                   "it under the terms of the GNU General Public License as "
                   "published by\n"
                   "the Free Software Foundation; either version 2 of the "
                   "License, or\n"
                   "(at your option) any later version.\n" );
            exit(0);
        case 'h':
            usage();
            exit(0);
        case 'b':
            sqlite3_dbpath = strdup(optarg);
            ext_db = 1;
            break;
        case 'a':
            Argc = argc;
            Argv = argv;
            user_ops(strdup(optarg), ADD_USER);
            fprintf(stderr, "Never here\n");
            exit(2);
        case 'y':
            yubikey_table = 1;
            break;
        case 'o':
            oath_table = 1;
            break;
        case 'p':
            api_table = 1;
            break;
        case 'l':
            show_table();
            exit(0);
        case 'e':
            user_ops(strdup(optarg), ENABLE_USER);
            fprintf(stderr, "Never here\n");
            exit(2);
        case 'd':
            user_ops(strdup(optarg), DISABLE_USER);
            fprintf(stderr, "Never here\n");
            exit(2);
        case 'x':
            user_ops(strdup(optarg), DELETE_USER);
            fprintf(stderr, "Never here\n");
            exit(2);
        }
    }
    exit(0);
}
