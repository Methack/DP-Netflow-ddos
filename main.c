#include <libnf.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define STRING_MAX 1024

typedef struct Ndd_rec_t Ndd_rec_t;

typedef struct {
        lnf_filter_t *filter;
        char *filter_string;
	Ndd_rec_t **stream;
	pthread_mutex_t stream_lock;
	int stream_elements_ready;
        char *db_table;
        int baseline_window;
        int max_newest_cutoff;
        int coefficient;
        int db_insert_interval;
        int db_columns[4];
}Ndd_filter_t;

const int col_count = 4;
const char col[4][16] = {"byte_baseline", "bps", "packet_baseline", "pps"};

char *connection_string;
char *nfcapd_current;

int filters_count = 0;
Ndd_filter_t **filters;


#include "db.c"
#include "config.c"
#include "ndd.c"


int main(){
	ndd_config_parse();

	process_file();

	for(int i = 0; i < filters_count; i++){
                ndd_free_filter(filters[i], 0);
        }

        free(filters);
        return 0;
}

