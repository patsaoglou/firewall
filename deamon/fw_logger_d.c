#include "fw_logger_d.h"

int init_fw_logger_d(fw_logger_d_st *handle)
{
    // this is going to be called from fw_main_d with thread create
    init_log_file(handle);
    init_fw_netlink_logger(handle);
    
    poll_logger(handle);
}

int deinit_fw_logger_d(fw_logger_d_st *handle)
{
    deinit_log_file(handle);
    deinit_fw_netlink_logger(handle);
}

int init_log_file(fw_logger_d_st *handle)
{   
    long file_s;
    time_t time_st;
    struct tm *time_info;
    char log_file_name[LOG_FILENAME_SIZE];

    time(&time_st);
    time_info = localtime(&time_st); 

    snprintf(log_file_name, LOG_FILENAME_SIZE, "%s/%2d%2d%d.log", LOG_FILE_DIR_PATH
                , time_info->tm_mday, time_info->tm_mon + 1, time_info->tm_year + 1900);
    
    handle->log_file = fopen(log_file_name, "a+");
    
    if (handle->log_file == NULL)
    {   
        printf("Failed to create log file. Exit...");
        return -1;
    }

    fseek(handle->log_file, 0, SEEK_END);
    file_s = ftell(handle->log_file);

    // if new file add coloums
    if (file_s == 0)
    {
       fprintf(handle->log_file, "%s", CSV_COLUMNS);
       fflush(handle->log_file);

    }

    return 0;
}

int deinit_log_file(fw_logger_d_st *handle)
{
    if (handle->log_file != NULL)
    {
        fclose(handle->log_file);
    }

    return 0;
}


int write_log_file(fw_logger_d_st *handle, char *log_entry)
{   
    fprintf(handle->log_file, "%s", log_entry);
    fflush(handle->log_file);
    

    return 0;
}
// Example used: https://github.com/mwarning/netlink-examples/blob/master/unicast_example/nl_recv.c
int init_fw_netlink_logger(fw_logger_d_st *handle)
{   
    struct sockaddr_nl fw_user_logger_addr;
    struct nlmsghdr *netlink_message;
    struct msghdr message;
    struct iovec io;

    handle->log_netlink_fd = socket(PF_NETLINK, SOCK_RAW, FW_LOG_NETLINK);

    memset(&fw_user_logger_addr, 0, sizeof(fw_user_logger_addr));
    fw_user_logger_addr.nl_family = AF_NETLINK;
    fw_user_logger_addr.nl_pid = getpid();
    fw_user_logger_addr.nl_groups = 0;
    bind(handle->log_netlink_fd, (struct sockaddr*)&fw_user_logger_addr, sizeof(fw_user_logger_addr));

    netlink_message = (struct nlmsghdr *)malloc(NLMSG_SPACE(LOG_PAYLOAD));

    memset(netlink_message, 0, NLMSG_SPACE(LOG_PAYLOAD));

    netlink_message->nlmsg_len = NLMSG_SPACE(LOG_PAYLOAD);
    netlink_message->nlmsg_pid = getpid();
    netlink_message->nlmsg_flags = 0;
    netlink_message->nlmsg_type = 0;

    memset(&io, 0, sizeof(io));
    io.iov_base = (void *)netlink_message;
    io.iov_len = NLMSG_SPACE(LOG_PAYLOAD);
    
    memset(&message, 0, sizeof(message));
    message.msg_iov = &io;
    message.msg_iovlen = 1;

    // send dummy message for the kernel module to get pid of deamon
    sendmsg(handle->log_netlink_fd, &message, 0);
    
    // add sleep until event
    while (1)
    {
        recvmsg(handle->log_netlink_fd, &message, 0);
        write_log_file(handle, (char *)NLMSG_DATA(netlink_message));
    }


}

int deinit_fw_netlink_logger(fw_logger_d_st *handle)
{
    return 1;
}



void poll_logger(fw_logger_d_st *handle)
{
    while(1)
    {      

    }
}

int main(void)
{
    fw_logger_d_st handle;
    
    init_fw_logger_d(&handle);

}