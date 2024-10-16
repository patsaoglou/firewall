#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define PROC_PATH           "/proc/my_fw/log"
#define LOG_FILENAME_SIZE   64
#define LOG_FILE_DIR_PATH   "./"
#define LOG_BUFF_SIZE       128
#define CSV_COLUMNS          "SOURCE_IP, PROTOCOL, TIME, TYPE\n"

typedef struct 
{
    FILE *log_file;
    int log_proc;

    char log_buff[LOG_BUFF_SIZE];
}fw_logger_d_st;

int init_fw_logger_d(fw_logger_d_st *handle);
int deinit_fw_logger_d(fw_logger_d_st *handle);

void poll_logger(fw_logger_d_st *handle);

int init_log_file(fw_logger_d_st *handle);
int write_log_file(fw_logger_d_st *handle);
int deinit_log_file(fw_logger_d_st *handle);

int init_log_proc_file(fw_logger_d_st *handle);
int deinit_log_proc_file(fw_logger_d_st *handle);

void check_if_log_proc_has_log_entry(fw_logger_d_st *handle);
