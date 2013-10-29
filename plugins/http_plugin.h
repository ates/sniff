#define HTTP_PLUGIN_ID 1

/* HTTP methods */
#define GET     1
#define POST    2
#define PUT     3
#define DELETE  4
#define HEAD    5
#define OPTIONS 6
#define TRACE   7
#define CONNECT 8

struct http_filter {
    uint8_t method; /* HTTP method */
    uint32_t hosts[32]; /* 32 IP addresses per domain */
};

struct http_filter_stats {
    uint64_t pkts, bytes;
};
