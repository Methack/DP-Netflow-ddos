#include <libnf.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>


#define STRING_MAX 1024

typedef struct Ndd_rec_t Ndd_rec_t;

typedef struct {
    lnf_filter_t *filter;
    char *filter_string;
	Ndd_rec_t **stream;
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
}Ndd_filter_t;

const int col_count = 4;
const char col[4][16] = {"byte_baseline", "bps", "packet_baseline", "pps"};

const int items_count = 7;
const char items_text[7][10] = {"none", "srcip", "dstip", "prot", "srcport", "dstport", "tcp_flags"};
const int items[7] = {0, LNF_FLD_SRCADDR, LNF_FLD_DSTADDR, LNF_FLD_PROT, LNF_FLD_SRCPORT, LNF_FLD_DSTPORT, LNF_FLD_TCP_FLAGS};

char *connection_string;
char *nfcapd_current;

int filters_count = 0;
Ndd_filter_t **filters;

int active_filters_count = 0;
int active_filters_allocated = 0;
pthread_mutex_t active_filters_lock;
lnf_filter_t **active_filters;
char **active_filters_text;

#include "db.c"
#include "config.c"
#include "ndd.c"


int main(int argc, char **argv){
	ndd_config_parse();
	
	if(argc == 2){
		if(!daemonize()){
                	fprintf(stderr, "Failed to daemonize");
                	return 1;
        	}
	}
	process_file();
	

	for(int i = 0; i < filters_count; i++){
                ndd_free_filter(filters[i], i);
        }
	for(int i = 0; i < active_filters_count; i++){
		lnf_filter_free(active_filters[i]);
	}
	(void) argv;
        free(filters);
	free(active_filters);
        return 0;
}

