#include "fw_netfilter_if.h"

fw_netfilter_if_status init_fw_netfilter_if(fw_netfilter_if *fw_netfilter_if_handle)
{
    return FW_NETFILTER_IF_SUCCESS;
}

unsigned int fw_netfilter_hook_cb(void *priv,struct sk_buff *skb, const struct nf_hook_state *state)
{
    return FW_NETFILTER_IF_SUCCESS;
}