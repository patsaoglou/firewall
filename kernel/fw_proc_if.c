#include "fw_proc_if.h"

MODULE_LICENSE("Dual MIT/GPL");

// struct for proc operation callbacks
static const struct file_operations mng_cb = {
    .read = mng_read_cb,
    .write = mng_write_cb
};

static const struct file_operations log_cb = {
    .read = log_read_cb,
    .write = log_write_cb
};

int init_fw_proc_if(fw_proc_if_st *fw_proc_if_handle)
{
    int state;

    state = register_fw_proc_if_dir(fw_proc_if_handle);
    if (state != FW_PROC_IF_SUCCESS)
    {
        return FW_PROC_IF_FAIL;
    }
    
    state = register_fw_mng(fw_proc_if_handle);
    if (state != FW_PROC_IF_SUCCESS)
    {
        return FW_PROC_IF_FAIL;
    }

    state = register_fw_log(fw_proc_if_handle);
    if (state != FW_PROC_IF_SUCCESS)
    {
        return FW_PROC_IF_FAIL;
    }

    return FW_PROC_IF_SUCCESS;
}

int register_fw_proc_if_dir(fw_proc_if_st *fw_proc_if_handle)
{
    fw_proc_if_handle->fw_proc_if_dentry = proc_mkdir(FW_PROC_DENTRY_NAME, NULL);

    if (fw_proc_if_handle->fw_proc_if_dentry == NULL)
    {
        printk(KERN_INFO "Error creating a directory entry into proc.");

        return FW_PROC_IF_FAIL;
    }

    return FW_PROC_IF_SUCCESS;
}


int register_fw_mng(fw_proc_if_st *fw_proc_if_handle)
{
    // registering mng proc file with write permitions only 
    fw_proc_if_handle->fw_proc_if_mng = proc_create(FW_PROC_MNG_FILENAME, 0222, fw_proc_if_handle->fw_proc_if_dentry, &mng_cb);
    
    if (fw_proc_if_handle->fw_proc_if_mng == NULL)
    {
        printk(KERN_INFO "Error creating proc file entry mng.");
        handle_fw_proc_if_fail(fw_proc_if_handle);
    
        return FW_PROC_IF_FAIL;
    }
    return FW_PROC_IF_SUCCESS;

}

int register_fw_log(fw_proc_if_st *fw_proc_if_handle)
{
    // registering log proc file with read permitions only  
    fw_proc_if_handle->fw_proc_if_log = proc_create(FW_PROC_LOG_FILENAME, 0444, fw_proc_if_handle->fw_proc_if_dentry, &log_cb);

    if (fw_proc_if_handle->fw_proc_if_log == NULL)
    {
        printk(KERN_INFO "Error creating proc file entry log.");

        handle_fw_proc_if_fail(fw_proc_if_handle);

        return FW_PROC_IF_FAIL;
    }   

    return FW_PROC_IF_SUCCESS;
}

// wrapper for fw_proc_if de-initialization
void deinit_fw_proc_if(fw_proc_if_st *fw_proc_if_handle)
{
    printk(KERN_INFO "Deinitializing proc entries.");

    handle_fw_proc_if_fail(fw_proc_if_handle);
}


void handle_fw_proc_if_fail(fw_proc_if_st *fw_proc_if_handle)
{   
    // remove proc entry if there is a fw_proc_if fail
    if (fw_proc_if_handle->fw_proc_if_mng)
    {
        proc_remove(fw_proc_if_handle->fw_proc_if_mng);
    }

    if (fw_proc_if_handle->fw_proc_if_log)
    {
        proc_remove(fw_proc_if_handle->fw_proc_if_log);
    }

    if (fw_proc_if_handle->fw_proc_if_dentry)
    {
        proc_remove(fw_proc_if_handle->fw_proc_if_dentry);
    }

}

ssize_t mng_read_cb(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
    return 1;
}

ssize_t mng_write_cb(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos)
{
    return 1;
}

ssize_t log_read_cb(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
    return 1;
}

ssize_t log_write_cb(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos)
{
    return 1;
}
