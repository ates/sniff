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

static int http_plugin_filter_skb(
    struct pf_ring_socket *ring,
    sw_filtering_rule_element *rule,
    struct pfring_pkthdr *hdr,
    struct sk_buff *skb, int displ,
    struct parse_buffer **parse_memory)
{
    struct http_filter *rule_filter = (struct http_filter*)rule->rule.extended_fields.filter_plugin_data;

    int i = 0, method = 0;
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
                    printk(KERN_INFO "HOST MATCH: %u - %u\n", hdr->extended_hdr.parsed_pkt.ip_dst.v4, rule_filter->hosts[i]);

                    if (!memcmp(payload, "GET", 3)) method = 1;

                    if (method == rule_filter->method)
                        return 1;
                    else
                        return 0;
                }
            }
            i++;
        }
    }
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
  reg.pfring_plugin_handle_skb = NULL;
  reg.pfring_plugin_get_stats  = NULL;
  reg.pfring_plugin_filter_skb = http_plugin_filter_skb;
  reg.pfring_plugin_register   = http_plugin_register;

  snprintf(reg.name, sizeof(reg.name) - 1, "http");
  snprintf(reg.description, sizeof(reg.description) - 1, "HTTP plugin");

  register_plugin(&reg);

  /* Make sure that PF_RING is loaded when this plugin is loaded */
  pf_ring_add_module_dependency();

  printk("HTTP plugin loaded [id=%d]\n", HTTP_PLUGIN_ID);

  return(0);
}

static void __exit http_plugin_exit(void)
{
    printk("HTTP plugin unloaded\n");
    unregister_plugin(HTTP_PLUGIN_ID);
}

module_init(http_plugin_init);
module_exit(http_plugin_exit);
MODULE_LICENSE("GPL");
