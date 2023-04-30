#ifndef __NDDSTRUCT_H_
#define __NDDSTRUCT_H_

#include <libnf.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "db.h"

#define LLUI long long unsigned int
#define STRING_MAX 1024
#define ERROR_MESSAGE 1
#define NORMAL_MESSAGE 0


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
        int filter_id;
        time_t time;
        char *message;

        struct Ndd_comm *next;
} ndd_comm_t;

typedef struct Ndd_activef{
        lnf_filter_t *filter;
        char *filter_string;
        uint64_t tstart;
        uint64_t tstop;

        struct Ndd_activef *next;
} ndd_activef_t;

//global variables
extern int write_stats;
extern int active_filters_count;
extern pthread_mutex_t active_filters_lock;
extern ndd_activef_t *active_filters;
extern ndd_comm_t *comm_top;
extern ndd_comm_t *comm_bot;
extern pthread_mutex_t comm_lock;
extern const int col_count;
extern const char col[4][16];
extern const int items_count;
extern const char items_text[7][10];


//struct functions
//ndd_rec_t
void ndd_init_rec(ndd_rec_t **rec, ndd_rec_t *last);
int ndd_clear_old_rec(ndd_rec_t **r, uint64_t cutoff);


//ndd_filter_t
void ndd_init_filter(ndd_filter_t **f, char *fs, char *t);
void ndd_free_filter(ndd_filter_t *f, int delete_table);
void ndd_print_filter_info(ndd_filter_t *f, int i, FILE *stream, char dest);

//ndd_comm_t
void ndd_init_comm(ndd_comm_t **c);
void ndd_free_comm(ndd_comm_t *c);
void ndd_fill_comm(char *string, int type, int filter_id);

//ndd_activef_t
void ndd_init_activef(ndd_activef_t **a);
void ndd_free_activef(ndd_activef_t *a);
int ndd_add_active_filter(lnf_filter_t *flt, char *filter_string, uint64_t duration, char *table);
int ndd_get_active_filters(lnf_filter_t **l);
void ndd_print_active_filters(FILE *stream);


#endif

