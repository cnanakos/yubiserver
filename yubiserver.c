/* Copyright (c) 2011 - 2014 Chrysostomos Nanakos <nanakos@wired-net.gr>
   Simple and lightweight Yubikey OTP-OATH/HOTP Validation Server

   yubiserver is placed under the GNU General Public License, version 2 or
   later.

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
#include <netdb.h>
#include <gcrypt.h>
#include <sqlite3.h>
#include <time.h>
#include <sys/timeb.h>
#include <getopt.h>
#include <math.h>
#include <mhash.h>
#include <sys/types.h>
#include <pwd.h>
#include <ev.h>
#include <libconfig.h>

#include "yubiserver.h"

static void yubilog(int type, const char *s1, const char *s2, int num)
{
    int fd;
    char *logbuffer = calloc(1, BUFSIZE * 2);

    switch (type)
    {
    case ERROR:
        snprintf(logbuffer, BUFSIZE * 2, "[ERROR] %s:%s errno=%d exiting pid=%d",
                s1, s2, errno, getpid());
        break;
    case WARNING:
        snprintf(logbuffer, BUFSIZE * 2,
                "<HTML><BODY><H2>Yubikey Validation Server Error: "
                "%s %s</H2></BODY></HTML>\r\n", s1, s2);
        write(num, logbuffer, strlen(logbuffer));
        snprintf(logbuffer, BUFSIZE * 2, "[WARNING] %s:%s", s1, s2);
        break;
    case LOG:
        snprintf(logbuffer, BUFSIZE * 2, "[INFO] %s:%s:%d", s1, s2, num);
        break;
    case REQUEST:
        snprintf(logbuffer, BUFSIZE * 2, "[REQUEST] %s", s1);
    }
    /* no checks here, nothing can be done a failure anyway */
    if((fd = open(yubiserver_log, O_CREAT| O_WRONLY | O_APPEND, 0644)) >= 0)
    {
        write(fd, logbuffer, strlen(logbuffer));
        write(fd, "\n", 1);
        close(fd);
    }
    free(logbuffer);
    /* Eroor is used in main and will exit if a syscall fail */
    if (type == ERROR)
    {
        exit(3);
    }
}

static void null_terminate(char *buffer)
{
    int i;
    /* null terminate after the second space to ignore extra stuff */
    for (i = 4; i < BUFSIZE; i++)
    {
        if (buffer[i] == ' ')
        { /* string is "GET URL " */
            buffer[i] = 0;
            break;
        }
    }
}

/* Decode Modhex to Hex */
static void modhex2hex(char *hex_otp, char *modhex_otp)
{
    char *end;
    char *hex = "0123456789abcdef";
    char *modhex = "cbdefghijklnrtuv";
    int i, pos;

    for (i = 0; i < strlen(modhex_otp); i++)
    {
        end = index(modhex, modhex_otp[i]);
        if (end == NULL)
        {
            goto out;
        }
        pos = end - modhex;
        hex_otp[i] = hex[pos];
    }
    return;
out:
    memcpy(hex_otp, modhex_otp, OTP_TOKEN);
    return;
}

/* Convert ASCII to Hexadecimal for OATH*/
static void oath_atoh(char *token, char *out)
{
    int temp, index;
    char buf[2]={' ','\0'};

    for (index = 0; index < 20; index++)
    {
        buf[0] = token[2 * index];
        temp = 16 * strtol(buf, NULL, 16);
        buf[0] = token[2 * index + 1];
        temp += strtol(buf, NULL, 16);
        out[index] = temp;
    }
}

/* Convert ASCII to Hexadecimal */
static void atoh(char *token,char *out)
{
    int temp, index;
    char buf[2] = {' ', '\0'};

    for (index = 0; index < 16; index++)
    {
        buf[0] = token[2 * index];
        temp = 16 * strtol(buf, NULL, 16);
        buf[0] = token[2 * index + 1];
        temp += strtol(buf, NULL, 16);
        out[index] = temp;
    }
}

/*Convert Hexadecimal to ASCII*/
static void htoa(char *token, char *out)
{
    int index;
    char *hex = "0123456789abcdef";

    for (index = 0; index < 16; index++)
    {
        snprintf((out + 2 * index), 2, "%c",
                hex[((unsigned char)token[index] / 16)]);
        snprintf((out + 2 * index + 1), 2, "%c",
                hex[((unsigned char)token[index] % 16)]);
    }
    /*BT_(out, OTP_MSG_SIZE);*/
}

/* Get Public ID from Encoded or Decoded OTP */
static void get_publicid(char *otp, char *pubid)
{
    int index;

    for (index = 0; index < 12; index++)
    {
        pubid[index] = otp[index];
    }
    BT_(pubid, PUBLIC_ID_SIZE);
}

/* Retrieve AES Key from Database */
static int get_aeskey(char *otp, char *aeskey, char *private_id)
{
    int retval, rows = 0;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    char *public_id = calloc(1, PUBLIC_ID_SIZE + 1);

    /* Get public id */
    get_publicid(otp, public_id);

    /* Create query for aeskey and private id */
    const char *query = "SELECT aeskey,internalname FROM yubikeys WHERE "
                        "publicname=? AND active='1'";

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG,"Database connection failed", 0, 0);
        free(public_id);
        return -1;
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG,"get_aeskey: Selecting data from DB failed", 0, 0);
        free(public_id);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, public_id, 12, 0);

    while (true)
    {
        retval = sqlite3_step(stmt);
        switch (retval)
        {
        case SQLITE_ROW:
            snprintf(aeskey, AES_SIZE + 1, "%s", sqlite3_column_text(stmt, 0));
            snprintf(private_id, PRIVATE_ID_SIZE + 1, "%s", sqlite3_column_text(stmt, 1));
            rows++;
            break;
        case SQLITE_DONE:
            break;
        default:
            yubilog(LOG,"Database error encountered", 0, 0);
            break;
        }
        if (retval != SQLITE_ROW)
        {
            break;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(handle);
    free(public_id);

    if (rows)
    {
         /* If user found return zero value */
        return 0;
    }
     /* If the user does not exist or is disabled
      * return negative value
      */
    return -1;
}

/* Decrypt AES encrypted OTP */
static char *aes128ecb_decrypt(char *otp,char *premod_otp, char *private_id)
{
    #define GCRY_CIPHER GCRY_CIPHER_AES128   // cipher
    #define GCRY_C_MODE GCRY_CIPHER_MODE_ECB // cipher mode
    gcry_error_t     gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    size_t otpLength  = 16;
    size_t keyLength  = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    char *decoded_otp = calloc(1, HEX_SIZE + 1);
    char *otp_token   = calloc(1, HEX_SIZE + 1);
    char *otp_buffer  = calloc(1, OTP_MSG_SIZE + 1);
    char *final_otp   = calloc(1, OTP_MSG_SIZE + 1);
    char *aesSymKey   = calloc(1, AES_SIZE + 1);
    char *aesKey      = calloc(1, HEX_SIZE + 1);

    int retval = get_aeskey(premod_otp, aesSymKey, private_id);
    if (retval < 0)
    {
        goto err_exit;
    }

    gcryError = gcry_cipher_open(
                                 &gcryCipherHd, // gcry_cipher_hd_t *
                                 GCRY_CIPHER,   // int
                                 GCRY_C_MODE,   // int
                                 0);            // unsigned int

    if (gcryError)
    {
        yubilog(LOG,"gcry_cipher_open failed",gcry_strsource(gcryError),0);
        goto err_exit;
    }
    atoh(aesSymKey, aesKey);
    BT_(aesKey, HEX_SIZE);

    gcryError = gcry_cipher_setkey(gcryCipherHd, aesKey, keyLength);
    if (gcryError)
    {
        yubilog(LOG,"gcry_cipher_setkey failed",gcry_strsource(gcryError),0);
        goto err_exit;
    }

    memcpy(otp_buffer, otp + 12, OTP_MSG_SIZE);
    BT_(otp_buffer, OTP_MSG_SIZE);

    atoh(otp_buffer, otp_token);
    BT_(otp_token, HEX_SIZE);

    gcryError = gcry_cipher_decrypt(
                                    gcryCipherHd, // gcry_cipher_hd_t
                                    decoded_otp,  // void *
                                    otpLength,    // size_t
                                    otp_token,    // const void *
                                    keyLength);   // size_t

    BT_(decoded_otp, HEX_SIZE);

    if (gcryError)
    {
        yubilog(LOG,"gcry_cipher_decrypt failed",gcry_strsource(gcryError),0);
        goto err_exit;
    }
    gcry_cipher_reset(gcryCipherHd);
    gcry_cipher_close(gcryCipherHd);

    htoa(decoded_otp, final_otp);

    free(decoded_otp);
    free(otp_token);
    free(otp_buffer);
    free(aesSymKey);
    free(aesKey);
    return final_otp;

err_exit:
    free(decoded_otp);
    free(otp_token);
    free(otp_buffer);
    free(final_otp);
    free(aesSymKey);
    free(aesKey);
    return NULL;
}

/* Compute CRC16-IBM {ANSI X3.28, Modbus,USB, Bisync}
 * (reversed polynomial representation (MSB-first code) = 0xA001)
 *
 */
static unsigned short crc16_ansi(unsigned char *token, unsigned int len)
{
    unsigned int j;
    unsigned short crc = 0xffff;
    unsigned char b, i;

    for (j = 0; j < len; j++)
    {
        b = token[j];
        for (i = 0; i < 8; i++)
        {
            crc = ((b ^ (unsigned char)crc) & 1) ? ((crc >> 1) ^ 0x8408) : (crc >> 1);
            b >>= 1;
        }
    }
    return crc;
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

static char *base64_encode(const unsigned char *data, size_t input_length,
                    size_t output_length)
{
    int i, j;
    output_length = (size_t) (4.0 * ceil((double) input_length / 3.0));
    char *encoded_data = calloc(1, output_length + 1);

    if (encoded_data == NULL)
    {
        return NULL;
    }

    for (i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
    {
        encoded_data[output_length - 1 - i] = '=';
    }
    encoded_data[output_length] = '\0';
    return encoded_data;
}


static int calc_counter(char *otp)
{
    static char chrotpcounter[7];
    snprintf(chrotpcounter, 3, "%.2s", (otp + 14));
    snprintf((chrotpcounter + 2), 3, "%.2s", (otp + 12));
    snprintf((chrotpcounter + 4), 3, "%.2s", (otp + 22));
    return (int)strtol(chrotpcounter, NULL, 16);
}

static int calc_timestamp(char *otp)
{
    static char chrotptimestamp[7];
    snprintf(chrotptimestamp, 3, "%.2s", (otp + 20));
    snprintf((chrotptimestamp + 2), 3, "%.2s", (otp + 18));
    snprintf((chrotptimestamp + 4), 3, "%.2s", (otp + 16));
    return (int)strtol(chrotptimestamp, NULL, 16);
}

static int calc_sessioncounter(char *otp)
{
    static char chrotpcounter[5];
    snprintf(chrotpcounter, 3, "%.2s", (otp + 14));
    snprintf((chrotpcounter + 2), 3, "%.2s", (otp + 12));
    return (int)strtol(chrotpcounter, NULL, 16);
}

static int calc_sessiontokencounter(char *otp)
{
    static char chrotpcounter[3];
    snprintf(chrotpcounter, 3, "%.2s", (otp + 22));
    return (int)strtol(chrotpcounter, NULL, 16);
}

static int sqlite3_countertimestamp(char *otp, int *db_counter,
                                    int *db_timestamp,
                                    struct Yubikey *yubikey)
{
    int retval, rows = 0;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    char * public_id =calloc(1, PRIVATE_ID_SIZE + 1);

    /* Get public_id*/
    get_publicid(otp, public_id);

    /* Create query for counter and time */
    const char *query = "SELECT counter,time,created FROM yubikeys WHERE "
                        "publicname=? AND active='1'";
    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG,"Database connection failed",0,0);
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG,"sqlite3_countertimestamp: "
                "Selecting data from DB failed", 0, 0);
        free(public_id);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, public_id, 12, 0);

    while (true)
    {
        retval = sqlite3_step(stmt);
        switch (retval)
        {
        case SQLITE_ROW:
            *db_counter = atoi((const char *)sqlite3_column_text(stmt, 0));
            *db_timestamp = atoi((const char *)sqlite3_column_text(stmt, 1));
            snprintf(yubikey->creation_date, 25, "%.24s",
                     sqlite3_column_text(stmt, 2));
            rows++;
            break;
        case SQLITE_DONE:
            break;
        default:
            yubilog(LOG,"sqlite3_countertimestamp: "
                    "Database error encountered", 0, 0);
            break;
        }
        if (retval != SQLITE_ROW)
        {
            break;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(handle);
    free(public_id);

    if (rows)
    {
        /* If user found return zero */
        return 0;
    }
     /* If the user does not exist return -1 */
    return -1;
}

/* Update SQLITE3 counter and timestamp */
static void sqlite3_updatecounter(char *otp, int counter, int timestamp)
{
    int retval;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    char *public_id = calloc(1, PUBLIC_ID_SIZE + 1);

    /* Get public_id*/
    get_publicid(otp,public_id);

    /* Update counter and time */
    const char *query = "UPDATE yubikeys SET counter=?,time=? WHERE "
                        "publicname=? AND active='1'";

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG,"sqlite3_updatecounter: Database connection failed", 0, 0);
        free(public_id);
        return;
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if(retval != SQLITE_OK)
    {
        yubilog(LOG, "sqlite3_updatecounter: Preparing handle failed", 0, 0);
        goto err_out;
    }

    sqlite3_bind_int(stmt, 1, counter);
    sqlite3_bind_int(stmt, 2, timestamp);
    sqlite3_bind_text(stmt, 3, public_id, 12, 0);

    retval = sqlite3_step(stmt);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG,"sqlite3_updatecounter:Updating counter/timestamp "
                    "data to DB failed",0,0);
    }

err_out:
    sqlite3_finalize(stmt);
    sqlite3_close(handle);

    free(public_id);
}

static char *get_apikey(char *id)
{
    int retval, rows = 0;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    char *secret = calloc(1, 40 + 1);

    /* Create query for aeskey and private id */
    const char *query = "SELECT secret FROM apikeys WHERE id=?";
    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG, "get_apikey: Database connection failed", 0, 0);
        free(secret);
        return NULL;
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG, "get_apikey: Selecting data from DB failed", 0, 0);
        goto err_out;
    }

    sqlite3_bind_text(stmt, 1, id, strlen(id), 0);

    while (true)
    {
        retval = sqlite3_step(stmt);
        switch (retval)
        {
        case SQLITE_ROW:
            snprintf(secret, 41, "%s", sqlite3_column_text(stmt, 0));
            rows++;
            break;
        case SQLITE_DONE:
            break;
        default:
            yubilog(LOG, "get_apikey: Database error encountered", 0, 0);
            break;
        }
        if (retval != SQLITE_ROW)
        {
            break;
        }
    }

err_out:
    sqlite3_finalize(stmt);
    sqlite3_close(handle);

    if (rows)
    {
         /* If user found return secret */
        return secret;
    }
    free(secret);
     /* If the user does not exist or
      * is deactivated return NULL
      */
    return NULL;
}

/* Validate OTP */
static int validate_otp(char *otp, char *premod_otp, char *private_id,
                        struct Yubikey *yubikey)
{
    int otp_counter, otp_timestamp;
    int db_counter, db_timestamp;
    int retval;
    unsigned short crc = 0;
    unsigned char * bcrc = calloc(1, CRC_BLOCK_SIZE);

    if (strncmp(otp, private_id, PRIVATE_ID_SIZE) != 0 )
    {
        free(bcrc);
        return BAD_OTP;
    }

    /* Get CRC16 */
    atoh(otp, (char *)bcrc);
    crc = crc16_ansi(bcrc, CRC_BLOCK_SIZE);
    free(bcrc);

    if (crc != CRC_OK)
    {
        return BAD_OTP;
    }

    /* Compute internal counter and timestamp */
    otp_counter = calc_counter(otp);
    otp_timestamp = calc_timestamp(otp);
    /* Fetch internal counter and timestamp from the database */
    retval = sqlite3_countertimestamp(premod_otp, &db_counter, &db_timestamp,
                                      yubikey);

    if (retval < 0)
    {
        yubikey->result = BAD_OTP;
        return BAD_OTP;
    }
    /* Do timestamp and internal counter checks */
    if (db_counter >= otp_counter)
    {
        yubikey->result = REPLAYED_OTP;
        return REPLAYED_OTP;
    }

    if ((db_timestamp >= otp_timestamp) &&
            ((db_counter >> 8) == (otp_counter >> 8)))
    {
        yubikey->result = DELAYED_OTP;
        return DELAYED_OTP;
    }

    yubikey->counter = otp_counter;
    yubikey->timestamp = otp_timestamp;
    yubikey->session_counter = calc_sessioncounter(otp);
    yubikey->session_token_counter = calc_sessiontokencounter(otp);
    yubikey->result = OK;

    return OK;
}

/* Create HMAC-SHA1-BASE64 Encoded string */
static char *create_hmac(char *otp, char *status, char *datetime, char *id,
                         char *nonce)
{
    int keylen, datalen;
    unsigned char mac[20];
    char *data = NULL, *output;
    MHASH td;

    char *password = get_apikey(id);

    if (password == NULL)
    {
         return NULL;
    }

    keylen = strlen(password);
    data = calloc(1, 180);
    if (nonce != NULL)
    {
        snprintf(data, 180, "nonce=%s&otp=%s&sl=100&status=%s&t=%s",
                           nonce, otp, status, datetime);
    }
    else
    {
        snprintf(data, 180, "otp=%s&sl=100&status=%s&t=%s",
                           otp, status, datetime);
    }
    datalen = strlen(data);

    td = mhash_hmac_init(MHASH_SHA1, password, keylen,
                         mhash_get_hash_pblock(MHASH_SHA1));
    mhash(td, data, datalen);
    mhash_hmac_deinit(td, mac);
    output = base64_encode(mac, 20, 20);

    free(data);
    free(password);
    return output;
}

static char *hotp(char *key, long counter, int digits)
{
    int bin_code, offset;
    unsigned char hmac_result[20];
    char *final_hotp = NULL;
    MHASH td;

    char Counter[8]= {
        ((long)counter >> 56) & 0xff, ((long)counter >> 48) & 0xff,
        ((long)counter >> 40) & 0xff, ((long)counter >> 32) & 0xff,
        ((long)counter >> 24) & 0xff, ((long)counter >> 16) & 0xff,
        ((long)counter >> 8)  & 0xff, ((long)counter >> 0)  & 0xff
    };

    char *HOTP = calloc(1, 20);

    td = mhash_hmac_init(MHASH_SHA1, key, strlen(key),
                         mhash_get_hash_pblock(MHASH_SHA1));

    mhash(td, Counter, 8); /* Hashing length is fixed to 8, always */
    mhash_hmac_deinit(td, hmac_result);

    offset = hmac_result[19] & 0xf ;

    bin_code = (hmac_result[offset]  & 0x7f) << 24
        | (hmac_result[offset + 1] & 0xff) << 16
        | (hmac_result[offset + 2] & 0xff) <<  8
        | (hmac_result[offset + 3] & 0xff);

    snprintf(HOTP, 20, "%d", bin_code);

    final_hotp = calloc(1, digits + 1);
     /* Digits is usually 6 */
    memcpy(final_hotp, HOTP + strlen(HOTP) - digits, digits);
    BT_(final_hotp, digits);

    free(HOTP);
    return final_hotp;
}

static struct Yubikey *oath_counter_secret(char *id)
{
    int retval, rows = 0;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    struct Yubikey *oyubikey = (struct Yubikey *)calloc(1, sizeof(*oyubikey));

    const char *query= "SELECT counter,secret FROM oathtokens WHERE "
                       "publicname=? AND active='1'";
    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG,"oath_counter_secret: Database connection failed", 0, 0);
        free(oyubikey);
        return NULL;
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG,"oath_counter_secret: Selecting data from DB failed",
                0, 0);
        goto err_out;
    }

    sqlite3_bind_text(stmt, 1, id, 12, 0);

    while (true)
    {
        retval = sqlite3_step(stmt);
        switch (retval)
        {
        case SQLITE_ROW:
            oyubikey->counter = atoi((const char *)sqlite3_column_text(stmt, 0));
            snprintf(oyubikey->oprivate_id, OPRIVATE_ID_SIZE + 1, "%s",
                     sqlite3_column_text(stmt, 1));
            rows++;
            break;
        case SQLITE_DONE:
            break;
        default:
            yubilog(LOG,"oath_counter_secret: Database error encountered",
                    0, 0);
            break;
        }
        if (retval != SQLITE_ROW)
        {
            break;
        }
    }

err_out:
    sqlite3_finalize(stmt);
    sqlite3_close(handle);

    /* If user found return secret */
    if (rows)
    {
        return oyubikey;
    }
    free(oyubikey);
    /* If the user does not exist or is deactivated return NULL */
    return NULL;
}

static void sqlite3_oath_updatecounter(char *otp, int counter)
{
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    int retval;
    char *public_id = calloc(1, PUBLIC_ID_SIZE + 1);

    /* Get public_id*/
    get_publicid(otp, public_id);

    /* Update counter */
    const char *query = "UPDATE oathtokens SET counter=? WHERE "
                        "publicname=? AND active='1'";

    retval = sqlite3_open(sqlite3_dbpath, &handle);

    if (retval)
    {
        yubilog(LOG, "sqlite3_oath_updatecounter: Database connection failed",
                0, 0);
        free(public_id);
        return;
    }

    retval = sqlite3_prepare_v2(handle, query, strlen(query), &stmt, 0);

    if (retval != SQLITE_OK)
    {
        yubilog(LOG, "sqlite3_oath_updatecounter: Preparing handle failed",
                0, 0);
        goto err_out;
    }

    sqlite3_bind_int(stmt, 1, counter);
    sqlite3_bind_text(stmt, 2, public_id, 12, 0);

    retval = sqlite3_step(stmt);

    if (retval)
    {
        yubilog(LOG,"sqlite3_oath_updatecounter:Updating counter/timestamp "
                    "data to DB failed", 0, 0);
    }

err_out:
    free(public_id);

    sqlite3_finalize(stmt);
    sqlite3_close(handle);
}

/* Validate HOTP/OATH */
static int validate_hotp(char *id, char *otp, struct OATH_Tokens *tokens)
{

    char *tokenid = calloc(1, PUBLIC_ID_SIZE + 1);
    char *hotp_val = NULL;
    char *Key = NULL;
    char *temp = NULL;
    int counter, retval;

    get_publicid(otp, tokenid);
    struct Yubikey *oyubikey = oath_counter_secret(tokenid);

    if (oyubikey == NULL)
    {
        free(tokenid);
        return BAD_OTP;
    }

    hotp_val = calloc(1, strlen(otp) - 12 + 1);
    snprintf(hotp_val, strlen(otp) - 12 + 1, "%s", otp + 12);
    if (strlen(hotp_val) % 2 != 0)
    {
        free(tokenid);
        free(hotp_val);
        free(oyubikey);
        return BAD_OTP;
    }
    Key = calloc(1, 20 + 1);
    oath_atoh(oyubikey->oprivate_id, Key);
    BT_(Key, 20);

    for (counter= 1 + oyubikey->counter ; counter < 256 + oyubikey->counter;
            counter++)
    {
        temp = hotp(Key, counter, strlen(hotp_val));
        if (!strcmp(hotp_val, temp))
        {
            tokens->counter = counter;
            if (temp)
            {
                free(temp);
            }
            retval = OK;
            goto out;
        }
        free(temp);
    }
    retval = NO_AUTH;
out:
    free(Key);
    free(oyubikey);
    free(hotp_val);
    free(tokenid);
    return retval;
}
/* Validate OTP-HOTP/OATH */
static int validate_all(char *otp, char *premod_otp, char *private_id,
                        char *id, struct Yubikey *yubikey,
                        struct OATH_Tokens *tokens, int method)
{
    int retval = BAD_OTP;
    switch (method)
    {
    case METHOD_OTP:
        retval = validate_otp(otp, premod_otp, private_id, yubikey);
        break;
    case METHOD_OATH:
        retval = validate_hotp(id, otp, tokens);
        break;
    default:
        break;
    }
    return retval;
}

static char *find_token(char *token)
{
    char *token1;
    token1 = strtok(token, "=");
    token1 = strtok(NULL, "\0");
    return token1;
}

static struct Tokens *tokenize(char *buffer)
{
    int j, i = 0;
    struct Tokens *tokens  = (struct Tokens *)calloc(1, sizeof(struct Tokens));
    char *token1,*token[7];

    tokens->id = NULL;
    tokens->otp = NULL;
    tokens->h = NULL;
    tokens->timestamp = NULL;
    tokens->nonce = NULL;
    tokens->sl = NULL;
    tokens->timeout = 0;

    token[0] = strtok(buffer, " ");
    token1   = strtok(NULL, " ");
    token1   = strtok(token1, "?");
    token[0] = strtok(NULL, "&");

    while (token[i] != NULL)
    {
        i++;
        token[i] = strtok(NULL,"&");
    }

    for (j = 0; j <= i - 1; j++)
    {
        if (strstr(token[j], "id=") != NULL)
        {
            tokens->id = find_token(token[j]);
        }
        if (strstr(token[j], "otp=") != NULL)
        {
            tokens->otp = find_token(token[j]);
        }
        if (strstr(token[j], "h=") != NULL)
        {
            tokens->h = find_token(token[j]);
        }
        if (strstr(token[j], "timestamp=") != NULL)
        {
            tokens->timestamp = find_token(token[j]);
        }
        if (strstr(token[j], "nonce=") != NULL)
        {
            tokens->nonce = find_token(token[j]);
        }
        if (strstr(token[j], "sl=") != NULL)
        {
            tokens->sl = find_token(token[j]);
        }
        if (strstr(token[j], "timeout=") != NULL)
        {
            tokens->timeout = atoi(find_token(token[j]));
        }
    }
    return tokens;
}

static struct OATH_Tokens *oath_tokenize(char *buffer)
{
    struct OATH_Tokens *tokens = (struct OATH_Tokens *)calloc(1,
                                                              sizeof(*tokens));
    int j, i = 0;
    char *token1, *token[7];
    tokens->id = NULL;
    tokens->otp = NULL;

    token[0] = strtok(buffer, " ");
    token1   = strtok(NULL, " ");
    token1   = strtok(token1, "?");
    token[0] = strtok(NULL, "&");
    while (token[i] != NULL)
    {
        i++;
        token[i] = strtok(NULL, "&");
    }

    for (j=0; j <= i-1; j++)
    {
        if (strstr(token[j], "otp=") != NULL)
        {
            tokens->otp = find_token(token[j]);
        }
        if (strstr(token[j], "id=") != NULL)
        {
            tokens->id = find_token(token[j]);
        }
    }
    return tokens;
}

/* Child authentication server process, exit on errors */
static void write_callback(struct ev_loop *loop, struct ev_io *w, int revents)
{
    long i, ret;
    static char ipv4_addr[INET_ADDRSTRLEN]; /* We do not support IPv6 */
    static char validation_date[DATE_BUFSIZE];
    static char datetmp[20];
    char *fstr = NULL, *otp = NULL, *hmac = NULL, *private_id = NULL;
    struct Tokens  *tokens = NULL;
    struct OATH_Tokens  *oath_tokens = NULL;
    time_t t;
    struct tm *tmp = NULL;
    struct timeb tp;
    int result = BAD_OTP;
    int sessioncounter = 0,sessionuse = 0,session_ts = 0;
    int sl = -1;
    char *status[12] = {"OK","BAD_OTP","REPLAYED_OTP","DELAYED_OTP",
                        "NO_SUCH_CLIENT","BAD_SIGNATURE","MISSING_PARAMETER",
                        "OPERATION_NOT_ALLOWED","BACKEND_ERROR",
                        "NOT_ENOUGH_ANSWERS","REPLAYED_REQUEST","NO_AUTH"
    };
    struct Yubikey *yubikey = NULL;
    char *buffer = calloc(1, BUFSIZE + 1); /* zero filled */
    struct ev_client *cli= ((struct ev_client*) (((char*)w) - \
                            offsetof(struct ev_client,ev_write)));

    memcpy(buffer, cli->buffer, cli->ret);
    ret = cli->ret;
    /* read failure then stop now */
    if (ret == 0 || ret == -1)
    {
        if (revents & EV_WRITE)
        {
            ev_io_stop(EV_A_ w);
        }
        yubilog(LOG, "failed to read browser request", buffer, ret);
        goto read_error;
    }

    /* return code is valid chars */
    if (ret > 0 && ret < BUFSIZE)
    {
        buffer[ret] = 0;  /* terminate the buffer */
    }
    else
    {
        buffer[0] = 0;    /* twice again?? */
    }
    /* remove CF and LF characters */
    for (i = 0; i < ret; i++)
    {
        if(buffer[i] == '\r' || buffer[i] == '\n')
        {
            buffer[i] = '*';
        }
    }

    /*yubilog(LOG,"Client request",buffer,cli->fd);*/

    /* Check here for Yubikey OTP request */
    if (cli->mode == EV_VAL_OTP)
    {
        if (revents & EV_WRITE)
        {
            char *otp_n = NULL;
            fstr = calloc(1, BUFSIZE);
            private_id = calloc(1, PRIVATE_ID_SIZE + 1);
            yubikey = (struct Yubikey *)calloc(1, sizeof(struct Yubikey));
            null_terminate(buffer);

            /* Tokenize the buffer and retrieve main attributes */
            tokens = tokenize(buffer);

            if (tokens->otp != NULL)
            {
                otp = calloc(1, OTP_TOKEN + 1);
                if (strlen(tokens->otp) > OTP_TOKEN)
                {
                    BT_(tokens->otp, OTP_TOKEN);
                }
                modhex2hex(otp, tokens->otp);
                BT_(otp, OTP_TOKEN);
                otp_n = aes128ecb_decrypt(otp, tokens->otp, private_id);
                /* otp is now decrypted if it is valid and if user exists */
                if (otp != NULL)
                {
                    free(otp);
                }
            }
            else if (tokens->otp == NULL)
            {
                yubilog(LOG, "Only simple verification operations supported "
                             "for OTP, OTP is NULL", 0, cli->fd);
            }

            if (otp_n == NULL || strlen(tokens->otp) != OTP_TOKEN)
            {
                result = BAD_OTP;
            }
            else
            {
                result = validate_all(otp_n,
                                      tokens->otp,
                                      private_id,
                                      tokens->id,
                                      yubikey,
                                      NULL,
                                      METHOD_OTP); /*validate*/
            }

            t = time(NULL);
            ftime(&tp);
            tmp = localtime(&t);
            strftime(datetmp, 20, "%FT%T", tmp);
            snprintf(validation_date, DATE_BUFSIZE, "%s.%.3dZ", datetmp, tp.millitm);
            if (tokens->nonce != NULL)
            {
                if (strlen(tokens->nonce) < 16 || strlen(tokens->nonce) > 40)
                {
                    tokens->nonce = NULL;
                }
            }

            if (tokens->id != NULL)
            {
                 /* Add nonce when computing hash */
                hmac = create_hmac(tokens->otp,
                                   status[result],
                                   validation_date,
                                   tokens->id,
                                   tokens->nonce);
                if (hmac == NULL)
                {
                    result = NO_SUCH_CLIENT;
                }
            }
            if (tokens->timestamp != NULL)
            {
                if (atoi(tokens->timestamp) == 1)
                {
                    sessioncounter = yubikey->session_counter;
                    sessionuse = yubikey->session_token_counter;
                    session_ts = 1;
                }
            }
            if (tokens->sl != NULL)
            {
                sl = atoi(tokens->sl);
            }
            snprintf(fstr, BUFSIZE, "HTTP/1.%d 200 OK\r\nContent-Type: %s\r\n\r\n",
                     cli->protocol, "text/plain");
            write(cli->fd, fstr, strlen(fstr));

            if (session_ts && result == OK)
            {
                snprintf(fstr, BUFSIZE, "h=%s\r\n"
                                        "t=%s\r\n"
                                        "otp=%s\r\n"
                                        "nonce=%s\r\n"
                                        "sl=%d\r\n"
                                        "timestamp=%d\r\n"
                                        "sessioncounter=%d\r\n"
                                        "sessionuse=%d\r\n"
                                        "status=%s\r\n",
                                        hmac != NULL ? hmac : " ",
                                        validation_date, tokens->otp,
                                        tokens->nonce != NULL? tokens->nonce : " ",
                                        sl != -1 ? sl : 100, yubikey->timestamp,
                                        sessioncounter, sessionuse,
                                        status[result]);
            }
            else
            {
                snprintf(fstr,BUFSIZE, "h=%s\r\n"
                                       "t=%s\r\n"
                                       "otp=%s\r\n"
                                       "nonce=%s\r\n"
                                       "sl=%d\r\n"
                                       "status=%s\r\n",
                                       hmac != NULL ? hmac : " ",
                                       validation_date, tokens->otp,
                                       tokens->nonce != NULL? tokens->nonce : " ",
                                       sl != -1 ? sl : 100 , status[result]);
            }
            write(cli->fd, fstr, strlen(fstr));
            /* Update database internal counter and timestamp */
            /* We are doing it here because we don't want the user
             * to experience a small response delay
             */
            if (result == OK)
            {
                sqlite3_updatecounter(tokens->otp,
                                      yubikey->counter,
                                      yubikey->timestamp);
            }
            inet_ntop(AF_INET, &cli->client_addr.sin_addr.s_addr, ipv4_addr,
                      INET_ADDRSTRLEN);
            snprintf(fstr, BUFSIZE, "%s %s %.12s %s %s",
                     validation_date, ipv4_addr, tokens->otp, "YUBIKEY",
                     status[result]);
            yubilog(REQUEST, fstr, NULL, 0);

            free(private_id);
            free(yubikey);
            free(fstr);
            if (hmac)
            {
                free(hmac);
            }
            if (otp_n)
            {
                free(otp_n);
            }
            free(tokens);
            ev_io_stop(EV_A_ w);
        }
    } else if (cli->mode == EV_VAL_OATH) {
        /* Check here for OATH Yubikey request */
        if (revents & EV_WRITE)
        {
            fstr = calloc(1, BUFSIZE);
            null_terminate(buffer);
             /* Tokenize the buffer and retrieve main attributes */
            oath_tokens = oath_tokenize(buffer);
            t = time(NULL);
            ftime(&tp);
            tmp = localtime(&t);
            strftime(datetmp, 20, "%FT%T", tmp);
            snprintf(validation_date, DATE_BUFSIZE, "%s.%.3dZ", datetmp, tp.millitm);

            if (oath_tokens->otp != NULL &&
                    (strlen(oath_tokens->otp) == 18 ||
                     strlen(oath_tokens->otp) == 20))
            {
                result = validate_all(oath_tokens->otp,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      oath_tokens,
                                      METHOD_OATH);
            }
            else
            {
                result = 1;
                if (strlen(oath_tokens->otp) > 20)
                {
                    BT_(oath_tokens->otp, 20);
                }
            }
            snprintf(fstr,BUFSIZE, "HTTP/1.%d 200 OK\r\nContent-Type: %s\r\n\r\n",
                     cli->protocol, "text/plain");
            write(cli->fd, fstr, strlen(fstr));

            snprintf(fstr,BUFSIZE, "h=%s\r\nt=%s\r\notp=%s\r\nstatus=%s\r\n",
                     " ",validation_date, oath_tokens->otp, status[result]);

            write(cli->fd, fstr, strlen(fstr));
            if (result == OK)
            {
                sqlite3_oath_updatecounter(oath_tokens->otp,
                                           oath_tokens->counter);
            }
            inet_ntop(AF_INET, &cli->client_addr.sin_addr.s_addr, ipv4_addr,
                      INET_ADDRSTRLEN);
            snprintf(fstr, BUFSIZE, "%s %s %.12s %s %s",
                     validation_date, ipv4_addr, oath_tokens->otp, "OATH",
                     status[result]);
            yubilog(REQUEST, fstr, NULL, 0);

            free(fstr);
            free(oath_tokens);
            ev_io_stop(EV_A_ w);
        }
    } else if(cli->mode == EV_DEFAULT_PAGE) {
        /* Default HTTP/1.1 request */
        if (revents & EV_WRITE)
        {
            snprintf(buffer, BUFSIZE + 1, "HTTP/1.%d 200 OK\r\nContent-Type: %s\r\n\r\n",
                     cli->protocol, "text/html; charset=utf-8");
            write(cli->fd, buffer, strlen(buffer));

            snprintf(buffer, BUFSIZE + 1,
                     "<html>Yubico Yubikey:<br><form "
                     "action='/wsapi/2.0/verify' method='GET'> \
                     <input type='text' name='otp'><br><input "
                     "type='submit'></form><br>OATH/HOTP "
                     "tokens:<br> \
                     <form action='/wsapi/2.0/oauthverify' "
                     "method='GET'> \
                     <input type='text' name='otp'><br><input "
                     "type='submit'></form></html>\r\n");
            write(cli->fd, buffer, strlen(buffer));
            ev_io_stop(EV_A_ w);
        }
    } else {
        if (revents & EV_WRITE)
        {
            yubilog(WARNING, "Only simple verification operations "
                             "supported for OTP/OATH", buffer, cli->fd);
            ev_io_stop(EV_A_ w);
        }
    }
read_error:
    close(cli->fd); /* Don't let client to drain */
    free(buffer);
    free(cli);
}

void usage()
{
    fprintf(stderr,
            "Simple and lightweight Yubikey OTP and HOTP/OATH "
            "validation server.\n"
            "Version " VERSION_ ". Written and copyrights by "
            "Chrysostomos Nanakos.\n"
            "THIS SOFTWARE COMES WITH ABSOLUTELY NO WARRANTY! "
            "USE AT YOUR OWN RISK!\n"
            "\nUsage: yubiserver [options] \n\n"
            "Options supported:\n"
            "   --version  or -V	Print version information\n"
            "   --help     or -h	Print this help screen\n"
            "   --database or -d	Use this SQLite3 database file\n"
            "   --port     or -p	Port to bind the server. Default port is "
            "8000\n"
            "   --logfile  or -l	Use this as logfile. Default is '"
            YUBISERVER_LOG_PATH "'\n"
            "   --bind     or -b Bind to specific addresses. This can be specified multiple times.\n"
            "This version of yubiserver has been configured with '"
            SQLITE3_DB_PATH "' as its default\n"
            "SQLite3 database file.\n");
}

int setnonblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
    {
        return flags;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
    {
        return -1;
    }
    return 0;
}

static void read_callback(struct ev_loop *loop, struct ev_io *w, int revents)
{

    struct ev_client *cli = ((struct ev_client*) (((char*)w) - \
                            offsetof(struct ev_client,ev_read)));
    long r = 0;
    char rbuff[BUFSIZE + 1];
    if (revents & EV_READ)
    {
        r = read(cli->fd, &rbuff, BUFSIZE);
        rbuff[r] = '\0';
        cli->buffer = rbuff;
        cli->ret = r;
        if (!strncmp(rbuff, "GET / HTTP/1.0", 14))
        {
            cli->mode = EV_DEFAULT_PAGE;
            cli->protocol = 0;
        }
        else if (!strncmp(rbuff, "GET / HTTP/1.1", 14))
        {
            cli->mode = EV_DEFAULT_PAGE;
            cli->protocol = 1;
        }
        else if (!strncmp(rbuff, "GET /wsapi/2.0/verify", 21))
        {
            cli->mode = EV_VAL_OTP;
        }
        else if (!strncmp(rbuff, "GET /wsapi/2.0/oauthverify", 26))
        {
            cli->mode = EV_VAL_OATH;
        }
    }
    ev_io_stop(EV_A_ w);
    ev_io_init(&cli->ev_write, write_callback, cli->fd, EV_WRITE);
    ev_io_start(loop, &cli->ev_write);
}

static void accept_callback(struct ev_loop *loop, struct ev_io *w, int revents)
{
    int client_fd;
    struct ev_client *client;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    client_fd = accept(w->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1)
    {
        return;
    }

    client = calloc(1, sizeof(*client));
    client->fd = client_fd;
    client->client_addr = client_addr;
    if (setnonblock(client->fd) < 0)
    {
        yubilog(LOG, "failed to set client socket to non-blocking", 0, 0);
    }
    ev_io_init(&client->ev_read, read_callback, client->fd, EV_READ);
    ev_io_start(loop, &client->ev_read);
}


/*! This function looks up all hostnames found in bindname and creates and
 * binds the sockets accordingly. All sockets are finally put into listening
 * mode and returned within the array listenfd. The function uses
 * getaddrinfo(3) to lookup the addresses, thus any valid hostnames and/or IP
 * addresses are allowed, independent of IPv4 and IPv6.
 * @param bindport Pointer to a string containing a port number or service name
 * as found in /etc/services.
 * @param bindname NULL-terminated array of hostnames.
 * @param listenfd Pointer to array of ints which will receive the file
 * descriptors of the sockets.
 * @param fdcnt Maximum number of entries available in listenfd.
 * @return The function returns the number of sockets bound. In case of
 * parameter error, -1 is returned. The function does not return if any error
 * occurs during socket creation/binding/listening but exits directly by
 * calling yubilog(ERROR,...).
 */
static int socket_setup(const char *bindport, char * const *bindname, int *listenfd, int fdcnt)
{
   int reuseaddr_on = 1, s, scnt;
   struct addrinfo hints;
   struct addrinfo *result, *rp;

   /* safety check */
   if (bindport == NULL || bindname == NULL || listenfd == NULL || fdcnt < 0)
      return -1;

   for (scnt = 0; *bindname != NULL && scnt < fdcnt ; bindname++)
   {
      memset(&hints, 0, sizeof(struct addrinfo));
      hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
      hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
      hints.ai_flags = 0;
      hints.ai_protocol = 0;          /* Any protocol */

      if ((s = getaddrinfo(*bindname, bindport, &hints, &result)) != 0)
         yubilog(ERROR, "getaddrinfo", gai_strerror(s),0);

      for (rp = result; rp != NULL && scnt < fdcnt; rp = rp->ai_next)
      {
         if ((listenfd[scnt] = socket(rp->ai_family, rp->ai_socktype,
                     rp->ai_protocol)) == -1)
            continue;

         if (setsockopt(listenfd[scnt], SOL_SOCKET, SO_REUSEADDR,
                  &reuseaddr_on, sizeof(reuseaddr_on)) == -1)
            yubilog(ERROR, "setsockopt failed", NULL, 0);

         if (bind(listenfd[scnt], rp->ai_addr, rp->ai_addrlen) < 0)
            yubilog(ERROR,"system call","bind", 0);

         if (listen(listenfd[scnt],64) < 0)
            yubilog(ERROR, "system call", "listen", 0);

         if (setnonblock(listenfd[scnt]) < 0)
            yubilog(ERROR, "cannot set server listening socket to non-blocking", 0, 0);

         scnt++;
      }
      freeaddrinfo(result);
   }

   return scnt;
}

//#define EVFLAG_FORKCHECK 1

int main(int argc, char **argv)
{
    int i, listenfd[MAX_BIND_COUNT];
    int option_index = 0, c;
    char *portStr;
    char *bindname[MAX_BIND_COUNT + 1];
    int scnt = 0;

    /* EV */
    ev_io *ev_accept = (ev_io *)calloc(1, sizeof(ev_io));
    struct ev_loop *loop = ev_default_loop(0);

    struct option long_options[] = {
                                    /*Takes no parameters*/
                                    {"version",0,0,'V'},
                                    {"help",0,0,'h'},

                                    /*Takes parameters*/
                                    {"port",1,0,'p'},
                                    {"database",1,0,'d'},
                                    {"logfile",1,0,'l'},
                                    {"bind", 1, 0, 'b'}
    };
    /* Define default port */
    portStr = "8000";
    /* Check here for arguments and please write a usage/help message!*/
    while ((c = getopt_long(argc, argv, "Vhp:d:l:b:", long_options, &option_index))
            != -1)
    {

        switch (c)
        {
        case 'V':
            printf("yubiserver version " VERSION_ ". "
                   "Copyright (C) 2011 - 2014 Chrysostomos Nanakos.\n"
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
        case 'p':
            portStr = optarg;
            break;
        case 'd':
            sqlite3_dbpath = strdup(optarg);
            break;
        case 'l':
            yubiserver_log = strdup(optarg);
            break;
        case 'b':
            if (scnt < MAX_BIND_COUNT)
               bindname[scnt++] = optarg;
            else
               fprintf(stderr, "bind address '%s' ignored (increase MAX_BIND_COUNT and recompile)\n", optarg);
            break;
        }
    }
    /* NULL terminate array of bind names */
    if (!scnt)
       bindname[scnt++] = "0.0.0.0";
    bindname[scnt] = NULL;

    fprintf(stderr, "Database file used: %s\n", sqlite3_dbpath);
    fprintf(stderr, "Logfile used: %s\n", yubiserver_log);
    fprintf(stderr, "Server starting at port: %s\n", portStr);

    /* Become daemon + unstopable and no zombies children (= no wait()) */
    if (fork() != 0)
    {
        return 0; /* parent returns OK to shell */
    }

    signal(SIGCLD, SIG_IGN); /* ignore child death */
    signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */

    for (i = 0; i < 32; i++)
    {
        close(i);   /* close open files */
    }

    setpgrp(); /* break away from process group */
    /* drop privileges , change to yubiserver user */
    struct passwd *yubiserver_user = getpwnam("yubiserver");
    setreuid(yubiserver_user->pw_uid, yubiserver_user->pw_uid);
    setregid(yubiserver_user->pw_gid, yubiserver_user->pw_gid);

    if ((scnt = socket_setup(portStr, bindname, listenfd, MAX_BIND_COUNT)) < 1)
        yubilog(ERROR, "could not setup sockets", "socket_setup()", 0);

    /* Init library */
    gcry_control(GCRYCTL_ANY_INITIALIZATION_P);
    //gcry_check_version (NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);

    for (; scnt; scnt--)
        ev_io_init(ev_accept, accept_callback, listenfd[scnt - 1], EV_READ);
    ev_io_start(loop, ev_accept);
    ev_loop_fork(loop);
    ev_loop (loop, 0);
    return 0;
}
