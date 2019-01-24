#ifndef yubiserver_h__
#define yubiserver_h__

#include <ev.h>

#define VERSION_                "0.6"

#define BUFSIZE                 4096
#define ERROR                   42
#define WARNING                 43
#define LOG                     44
#define REQUEST                 45
#define METHOD_OTP              1
#define METHOD_OATH             2

#define OK                      0	/* The OTP is valid. */
#define BAD_OTP                 1	/* The OTP is invalid format. */
#define REPLAYED_OTP            2	/* The OTP has already been seen by the service. */
#define DELAYED_OTP             3
#define NO_SUCH_CLIENT          4	/* The request lacks a parameter. */
#define BAD_SIGNATURE           5	/* The HMAC signature verification failed. */
#define MISSING_PARAMETER       6	/* The request lacks a parameter. */
#define OPERATION_NOT_ALLOWED	7	/* The request id is not allowed to verify OTPs */
#define BACKEND_ERROR           8	/* Unexpected error in our server. Please contact us if you see this error. */
#define NOT_ENOUGH_ANSWERS      9	/* Server could not get requested number of syncs during before timeout */
#define REPLAYED_REQUEST        10	/* Server has seen the OTP/Nonce combination before */
#define NO_AUTH                 11	/* The OATH/HOTP is invalid. */

#define CRC_OK                  0xF0B8
#define CRC_BLOCK_SIZE          16
#define PRIVATE_ID_SIZE         12
#define PUBLIC_ID_SIZE          12
#define OPRIVATE_ID_SIZE        40
#define OTP_MSG_SIZE            32
#define OTP_TOKEN               44
#define AES_SIZE                32
#define HEX_SIZE                16
#define PUBLIC_NAME_SIZE        16
#define QUERY_SIZE              100
#define DATE_BUFSIZE            25

/* Yubiserver-admin Constants */
#define ENABLE_USER             0
#define DISABLE_USER            1
#define ADD_USER                2
#define DELETE_USER             3

/* EV Constants */
#define EV_DEFAULT_PAGE         1
#define EV_VAL_OTP              2
#define EV_VAL_OATH             3

#ifndef PATH_MAX
#define PATH_MAX                4096
#endif

/* maximum number of sockets to bind to */
#define MAX_BIND_COUNT          16

#define BT_(x,y)                (x[y]='\0')

/* Change default path to /etc/yubiserver/yubiserver.sqlite */
//#define SQLITE3_DB_PATH		"yubiserver.sqlite"
//#define YUBISERVER_LOG_PATH	"yubiserver.log"

char *sqlite3_dbpath = SQLITE3_DB_PATH;
char *yubiserver_log = YUBISERVER_LOG_PATH;

struct Yubikey {
    int result;                             /* Final Result after validation */
    char publicname[PUBLIC_NAME_SIZE + 1];  /* Database Public Name */
    char creation_date[DATE_BUFSIZE];       /* Database account creation datetime */
    char private_id[PRIVATE_ID_SIZE + 1];   /* Database private ID */
    char oprivate_id[OPRIVATE_ID_SIZE + 1]; /* Database OATH private ID */
    char aeskey[AES_SIZE + 1];              /* Database AES Key */
    int active;                             /* Account is active */
    int counter;                            /* Database counter */
    int timestamp;                          /* Database timestamp */
    int session_counter;                    /* Internal session counter */
    int session_token_counter;              /* Internal session token counter */
};

struct Tokens {
    char *id;           /* Specifies the requestor so that the end-point can
                           retrieve correct shared secret for signing the
                           response.
                         */
    char *otp;          /* The OTP from the YubiKey. */
    char *h;            /* The optional HMAC-SHA1 signature for the request. */
    char *timestamp;    /* Timestamp=1 requests timestamp and session counter
                           information the response
                         */
    char *nonce;        /* A 16 to 40 character long string with random unique
                           data
                         */
    char *sl;           /* A value 0 to 100 indicating percentage of syncing
                           required by client, or strings "fast" or "secure"
                           to use server-configured values; if absent, let the
                           server decides
                         */
    int timeout;        /* Number of seconds to wait for sync responses; if
                           absent, let the server decides
                         */
};

struct OATH_Tokens {
    char *id;
    char *otp;      /* OATH HMAC OTP */
    char *tokenid;  /* 12 characters public token ID/Name */
    int counter;    /* Internal Yubikey OATH/HOTP counter */
};

struct Config {
    char *sqlite3file;  /* SQLite3 Database File */
    char *yubilogfile;  /* Yubiserver Log File */
    int port;           /* Yubiserver Port */
};

struct ev_client {
    int fd;         /* Client's connection File Descriptor */
    int mode;       /* Authentication Mode */
    int protocol;   /* HTTP Protocol version */
    char *buffer;   /* Client socket buffer */
    long ret;       /* Length of read data from client socket */
    ev_io ev_read;  /* EV Read I/O Struct */
    ev_io ev_write; /* EV Write I/O Struct */
    struct sockaddr_in client_addr;
};


void *ys_calloc(size_t nmemb, size_t size);


#endif /* yubiserver_h */
