#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/uaccess.h>

#include "fw_netfilter_if.h"

#define FW_PROC_DENTRY_NAME     "my_fw"
#define FW_PROC_MNG_FILENAME    "mng"
#define FW_PROC_LOG_FILENAME    "log"

typedef struct
{
    //  dedicated directory entry for fw
    struct proc_dir_entry *fw_proc_if_dentry;

    // One file entry for mng and one for log
    struct proc_dir_entry *fw_proc_if_mng;
    struct proc_dir_entry *fw_proc_if_log;

    fw_netfilter_if *fw_netfilter_handle;
}fw_proc_if_st;

typedef enum
{
    FW_PROC_IF_SUCCESS,
    FW_PROC_IF_FAIL
}fw_proc_if_status;

fw_proc_if_status init_fw_proc_if(fw_proc_if_st *fw_proc_if_handle, fw_netfilter_if *fw_netfilter_handle_p);
void deinit_fw_proc_if(fw_proc_if_st *fw_proc_if_handle);

fw_proc_if_status register_fw_proc_if_dir(fw_proc_if_st *fw_proc_if_handle);

fw_proc_if_status register_fw_mng(fw_proc_if_st *fw_proc_if_handle);
fw_proc_if_status register_fw_log(fw_proc_if_st *fw_proc_if_handle);

ssize_t mng_write_cb(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos);
ssize_t log_read_cb(struct file *file, char __user *ubuf, size_t count, loff_t *ppos);

fw_proc_if_status handle_fw_proc_if_fail(fw_proc_if_st *fw_proc_if_handle);


