#include "fw_proc_if.h"

MODULE_LICENSE("Dual MIT/GPL");

// struct for proc operation callbacks
struct file_operations mng_cb = {
    .write = mng_write_cb
};

fw_proc_if_status init_fw_proc_if(fw_proc_if_st *fw_proc_if_handle, fw_netfilter_if *fw_netfilter_handle_p)
{
    int state;

    //  register fw_netfilter_handle to use netfilter interface
    fw_proc_if_handle->fw_netfilter_handle = fw_netfilter_handle_p;

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

    return FW_PROC_IF_SUCCESS;
}

fw_proc_if_status register_fw_proc_if_dir(fw_proc_if_st *fw_proc_if_handle)
{
    fw_proc_if_handle->fw_proc_if_dentry = proc_mkdir(FW_PROC_DENTRY_NAME, NULL);

    if (fw_proc_if_handle->fw_proc_if_dentry == NULL)
    {
        printk(KERN_INFO "%s: Error creating a directory entry into proc", KBUILD_MODNAME);

        return handle_fw_proc_if_fail(fw_proc_if_handle);
    }

    return FW_PROC_IF_SUCCESS;
}


fw_proc_if_status register_fw_mng(fw_proc_if_st *fw_proc_if_handle)
{
    // registering mng proc file with write permitions only 
    fw_proc_if_handle->fw_proc_if_mng = proc_create(FW_PROC_MNG_FILENAME, 0222, fw_proc_if_handle->fw_proc_if_dentry, &mng_cb);
    
    if (fw_proc_if_handle->fw_proc_if_mng == NULL)
    {
        printk(KERN_INFO "%s: Error creating proc file entry mng", KBUILD_MODNAME);
        handle_fw_proc_if_fail(fw_proc_if_handle);
    
        return handle_fw_proc_if_fail(fw_proc_if_handle);
    }
    return FW_PROC_IF_SUCCESS;

}


// wrapper for fw_proc_if de-initialization
void deinit_fw_proc_if(fw_proc_if_st *fw_proc_if_handle)
{
    printk(KERN_INFO "%s: Deinitializing proc entries", KBUILD_MODNAME);

    handle_fw_proc_if_fail(fw_proc_if_handle);
}


fw_proc_if_status handle_fw_proc_if_fail(fw_proc_if_st *fw_proc_if_handle)
{   
    // remove proc entry if there is a fw_proc_if fail
    if (fw_proc_if_handle->fw_proc_if_mng)
    {
        proc_remove(fw_proc_if_handle->fw_proc_if_mng);
    }

    if (fw_proc_if_handle->fw_proc_if_dentry)
    {
        proc_remove(fw_proc_if_handle->fw_proc_if_dentry);
    }

    return FW_PROC_IF_FAIL;
}

ssize_t mng_write_cb(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{   
    char test_buff[32];

    memset(test_buff, 0 , 32);


    if (copy_from_user(test_buff, ubuf, count))
    {
        printk(KERN_INFO "%s: mng_read_cb was envoked and failed", KBUILD_MODNAME);
        return -1;
    }
    
    printk(KERN_INFO "%s: mng_read_cb was good. Got: %s", KBUILD_MODNAME, test_buff);
    
    return count;
}