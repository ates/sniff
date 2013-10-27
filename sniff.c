#include <stdio.h>
#include <signal.h>
#include <ctype.h>

#include <netdb.h>
#include <netinet/in.h>

#include <pfring.h>

#include "plugins/http_plugin.h"

#define DEVICE "eth0"
#define SNAPLEN 1500
#define HOST "ya.ru"

static pfring *ring;

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

return;
}

static void process_packet(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes)
{
    print_payload(p, h->len);
}

static void sigproc(int sig)
{
    printf("Got signal %d\n", sig);
    pfring_close(ring);
}

int main(int argc, char *argv[])
{
    int i = 0;
    u_int32_t version;
    filtering_rule rule;
    struct http_filter *filter;

    struct hostent *tmp = 0;

    if ((ring = pfring_open(DEVICE, SNAPLEN, PF_RING_PROMISC)) == NULL)
    {
        printf("pfring_open failed for %s: %s\n", DEVICE, strerror(errno));
        return -1;
    }

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    pfring_version(ring, &version);
    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8, version & 0x000000FF);

    pfring_toggle_filtering_policy(ring, 0); /* Default to drop */

    memset(&rule, 0, sizeof(rule));
    
    rule.rule_id = 5;
    rule.rule_action = forward_packet_and_stop_rule_evaluation;
    rule.plugin_action.plugin_id = HTTP_PLUGIN_ID;
    rule.core_fields.proto = 6; /* TCP */
    rule.core_fields.dport_low = 80;
    rule.core_fields.dport_high = 80;
    rule.extended_fields.filter_plugin_id = HTTP_PLUGIN_ID; 
    filter = (struct http_filter *)rule.extended_fields.filter_plugin_data;

    tmp = gethostbyname(HOST);

    i = 0;
    printf("IP addresses for %s:\n", HOST);
    
    while(tmp->h_addr_list[i] != NULL) {
        printf("%u\n", ntohl(*((uint32_t *) tmp->h_addr_list[i])));
        filter->hosts[i] = ntohl(*((uint32_t *) tmp->h_addr_list[i]));
        i++;
    }

    filter->method = 1; // GET

    if (pfring_add_filtering_rule(ring, &rule) < 0) {
        printf("pfring_add_filtering_rule(2) failed: %s\n", strerror(errno));
        return 1;
    } else
        printf("Rule added successfully...\n");

    pfring_loop(ring, process_packet, (u_char *)NULL, 1);

    return 0;
}