#define HTTP_PLUGIN_ID 1

struct http_filter {
    int method;
    uint32_t hosts[16];
};
