#ifndef __NDD_H_
#define __NDD_H_

#include <libnf.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>

#include "nddstruct.h"
#include "db.h"
#include "comm.h"

//global variables
extern int stop;
extern int stop_number;
extern int active_filters_count;
extern pthread_mutex_t active_filters_lock;
extern ndd_activef_t *active_filters;
extern const int items[7];
extern char *nfcapd_current;

//ndd.c functions
void ndd_assemble_filepath(char path[], char *filter_name, uint64_t time, int time_index);
int ndd_write_to_new_file(ndd_rec_t *r, int filter_id, uint64_t new_time, uint64_t old_time, int time_index);
void *ndd_process_filter_stream(void *p);
int ndd_process_file();
void ndd_tcp_flags_decode(char on[], char off[], uint8_t flags, int *on_count);
int ndd_find_attack_pattern(uint64_t file_times[], int file_count, int filter_id, uint64_t threshold);

#endif

