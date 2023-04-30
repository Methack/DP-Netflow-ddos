#ifndef __COMM_H_
#define __COMM_H_


#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <libnf.h>

#include "nddstruct.h"

//global variables
extern ndd_comm_t *comm_top;
extern ndd_comm_t *comm_bot;
extern int print;
extern int logging;
extern int filters_count;
extern ndd_filter_t **filters;
extern pthread_mutex_t comm_lock;
extern int comm_stop;
extern int write_stats;

//comm.c functions
void *ndd_manage_io();

#endif

