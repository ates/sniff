#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x9a31bb74, "module_layout" },
	{ 0xfe769456, "unregister_netdevice_notifier" },
	{ 0x2bc09a00, "pf_ring_add_module_dependency" },
	{ 0x63ecad53, "register_netdevice_notifier" },
	{ 0x37a0cba, "kfree" },
	{ 0xd61adcbd, "kmem_cache_alloc_trace" },
	{ 0x5cd9dbb5, "kmalloc_caches" },
	{ 0x449ad0a7, "memcmp" },
	{ 0x27e1a049, "printk" },
	{ 0x94993346, "try_module_get" },
	{ 0x3cf78bf4, "module_put" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=pf_ring";


MODULE_INFO(srcversion, "516063EBAA33E872091DC3A");
