#ifndef __NDD_H_
#define __NDD_H_

#include <libnf.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>

#define LLUI long long unsigned int
#define STRING_MAX 1024

//typedef structures
typedef struct Ndd_rec{
        lnf_brec1_t brec;
        uint8_t tcp_flags;

        int processed;
        struct Ndd_rec *next;
        struct Ndd_rec *prev;
} ndd_rec_t;

typedef struct Ndd_filter {
        lnf_filter_t *filter;
        char *filter_string;
        ndd_rec_t **stream;
        pthread_mutex_t stream_lock;
        int stream_elements;
        char *db_table;
        int baseline_window;
        int dataset_window;
        int dataset_chunks;
        int eval_items[7];
        int required_items[7];
        int thstep;
        int thsteps;
        int max_baseline_increase;
        int max_newest_cutoff;
        int coefficient;
        int db_insert_interval;
        int db_columns[4];
}ndd_filter_t;

typedef struct Ndd_comm{
        //0 - normal | 1 - error
        uint8_t type;
        time_t time;
        char *message;

        struct Ndd_comm *next;
} ndd_comm_t;

//global variables
extern int stop;
extern int stop_number;
extern int active_filters_count;
extern int active_filters_allocated;
extern pthread_mutex_t active_filters_lock;
extern lnf_filter_t **active_filters;
extern char **active_filters_text;
extern const int items[7];


//ndd.c functions
void ndd_init_rec(ndd_rec_t **rec, ndd_rec_t *last);
int ndd_clear_old_rec(ndd_rec_t **r, uint64_t cutoff);

void ndd_assemble_filepath(char path[], char *filter_name, uint64_t time, int time_index);
int ndd_write_to_new_file(ndd_rec_t *r, int filter_id, uint64_t new_time, uint64_t old_time, int time_index);

void *ndd_process_filter_stream(void *p);

int ndd_process_file();

void ndd_tcp_flags_decode(char on[], char off[], uint8_t flags, int *on_count);
int ndd_add_active_filter(lnf_filter_t *f);

int ndd_find_attack_pattern(uint64_t file_times[], int file_count, int filter_id, uint64_t threshold);

#endif

