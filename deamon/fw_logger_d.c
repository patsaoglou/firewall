#include "fw_logger_d.h"

int init_fw_logger_d(fw_logger_d_st *handle)
{
    memset(handle->log_buff, 0, LOG_BUFF_SIZE);

    init_log_file(handle);
    init_log_proc_file(handle);
    return 0;
}

int deinit_fw_logger_d(fw_logger_d_st *handle)
{
    deinit_log_file(handle);
    deinit_log_proc_file(handle);
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


int write_log_file(fw_logger_d_st *handle)
{   
    fprintf(handle->log_file, "%s",handle->log_buff);
    fflush(handle->log_file);
    
    memset(handle->log_buff, 0, LOG_BUFF_SIZE);

    return 0;
}

int init_log_proc_file(fw_logger_d_st *handle)
{   
    handle->log_proc = open(PROC_PATH, O_RDONLY);
    
    if (handle->log_proc < 0)
    {   
        printf("Failed to open /proc/my_fw/log. Exit...");
        return -1;
    }

}

int deinit_log_proc_file(fw_logger_d_st *handle)
{
    if (handle->log_proc > 0)
    {
        close(handle->log_proc);
    }

    return 0;
}

void check_if_log_proc_has_log_entry(fw_logger_d_st *handle)
{
    size_t bytes_read;
    bytes_read = read(handle->log_proc, handle->log_buff, sizeof(handle->log_buff) - 1);
    printf("bytes_read: %ld\n", bytes_read);
    if (bytes_read < 0)
    {
        printf("Error reading proc. Exit");
        exit(0);
    }
    else if (bytes_read > 0)
    {
        write_log_file(handle);
    }
}

void poll_logger(fw_logger_d_st *handle)
{
    while(1)
    {      
        check_if_log_proc_has_log_entry(handle);
        sleep(1);
    }
}

int main(void)
{
    fw_logger_d_st handle;
    
    init_fw_logger_d(&handle);
    poll_logger(&handle);
}