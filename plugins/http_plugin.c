#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define PF_RING_PLUGIN
#include <linux/pf_ring.h>

#include "http_plugin.h"

static struct pfring_plugin_registration reg;

static int http_plugin_handle_skb(
        struct pf_ring_socket *pfr,
        sw_filtering_rule_element *rule,
        sw_filtering_hash_bucket *hash_rule,
        struct pfring_pkthdr *hdr,
        struct sk_buff *skb, int displ,
        u_int16_t filter_plugin_id,
        struct parse_buffer **filter_rule_memory_storage,
        rule_action_behaviour *behaviour)
{
    if(rule != NULL)
    {
        if(rule->plugin_data_ptr == NULL)
        {
            rule->plugin_data_ptr = (struct http_filter_stats *)kmalloc(sizeof(struct http_filter_stats), GFP_ATOMIC);

            if(rule->plugin_data_ptr != NULL)
                memset(rule->plugin_data_ptr, 0, sizeof(struct http_filter_stats));
        }

        if(rule->plugin_data_ptr != NULL) {
            struct http_filter_stats *stats = (struct http_filter_stats *)rule->plugin_data_ptr;
            stats->pkts++, stats->bytes += hdr->len;
        }
    }

    return 1;
}

static int http_plugin_filter_skb(
    struct pf_ring_socket *ring,
    sw_filtering_rule_element *rule,
    struct pfring_pkthdr *hdr,
    struct sk_buff *skb, int displ,
    struct parse_buffer **parse_memory)
{
    struct http_filter *rule_filter = (struct http_filter*)rule->rule.extended_fields.filter_plugin_data;

    int i = 0;
    uint8_t method = 0;
    u_int offset = 0;
    char *payload = 0;

    if (rule_filter) {
        while(rule_filter->hosts[i] != 0) {
            if (hdr->extended_hdr.parsed_pkt.ip_dst.v4 == rule_filter->hosts[i])
            {
                offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset;
                payload = &skb->data[offset];

                if (hdr->caplen > offset)
                {
                    if (!memcmp(payload, "GET", 3))     method = GET;
                    if (!memcmp(payload, "POST", 4))    method = POST;
                    if (!memcmp(payload, "PUT", 3))     method = PUT;
                    if (!memcmp(payload, "DELETE", 6))  method = DELETE;
                    if (!memcmp(payload, "HEAD", 4))    method = HEAD;
                    if (!memcmp(payload, "OPTIONS", 7)) method = OPTIONS;
                    if (!memcmp(payload, "TRACE", 5))   method = TRACE;
                    if (!memcmp(payload, "CONNECT", 7)) method = CONNECT;

                    return rule_filter->method == method ? 1 : 0;
                }
            }
            i++;
        }
    }
    return 0;
}

static int http_plugin_get_stats(
        struct pf_ring_socket *pfr,
        sw_filtering_rule_element *rule,
        sw_filtering_hash_bucket  *hash_bucket,
        u_char *stats_buffer,
        u_int stats_buffer_len)
{
    if(stats_buffer_len >= sizeof(struct http_filter_stats))
    {
        if(rule->plugin_data_ptr == NULL)
            memset(stats_buffer, 0, sizeof(struct http_filter_stats));
        else
            memcpy(stats_buffer, rule->plugin_data_ptr, sizeof(struct http_filter_stats));

        return(sizeof(struct http_filter_stats));
    } else
        return 0;
}

static void http_plugin_register(u_int8_t register_plugin)
{
    if(register_plugin)
        try_module_get(THIS_MODULE); /* Increment usage count */
    else
        module_put(THIS_MODULE);     /* Decrement usage count */
}

static int __init http_plugin_init(void)
{
  memset(&reg, 0, sizeof(reg));

  reg.plugin_id                = HTTP_PLUGIN_ID;
  reg.pfring_plugin_handle_skb = http_plugin_handle_skb;
  reg.pfring_plugin_filter_skb = http_plugin_filter_skb;
  reg.pfring_plugin_get_stats  = http_plugin_get_stats;
  reg.pfring_plugin_register   = http_plugin_register;

  snprintf(reg.name, sizeof(reg.name) - 1, "http");
  snprintf(reg.description, sizeof(reg.description) - 1, "HTTP plugin");

  register_plugin(&reg);

  /* Make sure that PF_RING is loaded when this plugin is loaded */
  pf_ring_add_module_dependency();

  printk("HTTP plugin loaded [id=%d]\n", HTTP_PLUGIN_ID);

  return 0;
}

static void __exit http_plugin_exit(void)
{
    printk("HTTP plugin unloaded\n");
    unregister_plugin(HTTP_PLUGIN_ID);
}

module_init(http_plugin_init);
module_exit(http_plugin_exit);
MODULE_LICENSE("GPL");
