#include <linux/netfilter.h>

#define FW_NETFILTER_LOG_BUFF_SIZE 128

typedef struct 
{
    // this buff is used by fw_proc_if to dump to /proc/my_fw/logv
    char log_dump[FW_NETFILTER_LOG_BUFF_SIZE];
    
    struct nf_hook_ops *fw_netfilter_hook;
}fw_netfilter_if;

typedef enum
{
    FW_NETFILTER_IF_SUCCESS,
    FW_NETFILTER_IF_FAIL
}fw_netfilter_if_status;


fw_netfilter_if_status init_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle);
void deinit_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle);

unsigned int fw_netfilter_hook_cb(void *priv,struct sk_buff *skb, const struct nf_hook_state *state);

