#ifndef _FW_LOGGER_D_H
#define _FW_LOGGER_D_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define LOG_PAYLOAD         128
#define LOG_FILENAME_SIZE   64
#define LOG_FILE_DIR_PATH   "./"
#define CSV_COLUMNS          "SOURCE_IP, PROTOCOL, TIME, TYPE\n"
#define FW_LOG_NETLINK      30

typedef struct 
{
    FILE *log_file;
    int log_netlink_fd;
}fw_logger_d_st;

int init_fw_logger_d(fw_logger_d_st *handle);
int deinit_fw_logger_d(fw_logger_d_st *handle);

void poll_logger(fw_logger_d_st *handle);

int init_log_file(fw_logger_d_st *handle);
int write_log_file(fw_logger_d_st *handle, char *log_entry);
int deinit_log_file(fw_logger_d_st *handle);

int init_fw_netlink_logger(fw_logger_d_st *handle);
int deinit_fw_netlink_logger(fw_logger_d_st *handle);

#endif