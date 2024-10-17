#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#define FW_LOG_NETLINK 30

typedef struct 
{
    struct sock *log_netlink;
    int fw_deamon_pid;
}fw_netlink_logger_if_st;

typedef enum
{
    FW_LOG_NETLINK_SUCCESS,
    FW_LOG_NETLINK_FAIL,
    FW_LOG_NETLINK_MES_SUCCESS,
    FW_LOG_NETLINK_MES_FAIL
}fw_netlink_logger_if_status;

fw_netlink_logger_if_status init_fw_netlink_if(fw_netlink_logger_if_st *fw_netlink_if_handle);
void deinit_fw_netlink_if(fw_netlink_logger_if_st *fw_netlink_if_handle);

void receive_fw_deamon_pid(struct sk_buff *skb);
fw_netlink_logger_if_status send_log_entry_netlink(fw_netlink_logger_if_st *fw_netlink_if_handle, char *log_entry, spinlock_t *log_spinlock);


