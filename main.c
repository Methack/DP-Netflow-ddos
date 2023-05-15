#include <libnf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

//from nfddos
int daemonize(){
	pid_t pid, sid;

	pid = fork();
	if(pid < 0){
		return 0;
	}

	if(pid > 0){
		exit(0);
	}
	sid = setsid();
	if(sid < 0){
		return 0;
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 1;
}

const int col_count = 4;
const char col[4][16] = {"byte_baseline", "bps", "packet_baseline", "pps"};

const int items_count = 7;
const char items_text[7][10] = {"none", "srcip", "dstip", "prot", "srcport", "dstport", "tcp_flags"};
const int items[7] = {0, LNF_FLD_SRCADDR, LNF_FLD_DSTADDR, LNF_FLD_PROT, LNF_FLD_SRCPORT, LNF_FLD_DSTPORT, LNF_FLD_TCP_FLAGS};

char *connection_string;
char *nfcapd_current;
char **nfcapd_files;
int file_count = 1;

int filters_count = 0;

int active_filters_count = 0;
pthread_mutex_t active_filters_lock;

pthread_mutex_t comm_lock;

int stop = 1;
int comm_stop = 1;
int write_stats = 1;
int stop_number = 0;
int loop_read = 1;
int print = 0;
int logging = 0;

#include "nddstruct.h"

ndd_filter_t **filters;
ndd_comm_t *comm_top = NULL;
ndd_comm_t *comm_bot = NULL;
ndd_activef_t *active_filters;

#include "db.h"
#include "comm.h"
#include "config.h"
#include "ndd.h"


int main(int argc, char **argv){
	int daemon = 0;
	int delete = 0;
	int c;
	while((c = getopt(argc, argv, "pdltrs:m:")) != -1){
		switch(c){
			case 'd' : {
				daemon = 1;
				break;		
			}
			case 'p' : {
				print = 1;
				break;		
			}
			case 's' : {
				stop_number = atoi(optarg);
				break;		
			}
			case 't' : {
				delete = 1;
				break;
			}
			case 'l' : {
				logging = 1;
				break;		
			}
			case 'r' : {
				loop_read = 0;
				break;
			}
			case 'm' : {
				file_count = atoi(optarg);
				break;	   
			}
			case '?' : {
				printf("Usage: %s [ -a ] [ -p ] [ -d ] [ -r ] [-m <number>] [ -s <number>]\n", argv[0]);
				printf(" -d : Daemonize program\n");
				printf(" -p : Print additional information\n");
				printf(" -t : Drop filter Tables after finishing\n");
				printf(" -l : Log into log files\n");
				printf(" -r : Read file not current\n");
				printf(" -m <n> : Number <n> of input-files, used only in combination with -r\n");
				printf(" -s <n> : Will Stop program after <n> db inserts\n");
				return 1;
			}
		
		}
	
	}
	
	if(loop_read)
		file_count = 1;

	ndd_config_parse();

	if(stop_number){
		printf("Will stop after %d db inserts\n", stop_number);
	}else if(!loop_read){
		printf("Will run until end of file\n");
	}else{
		printf("Will run indefinitely\n");
	}

	if(delete){
		printf("Will delete filter tables when finished\n");
	}
	if(logging){
		printf("Will be logging\n");
	}
	
	if(daemon){
		printf("Will daemonize now\n");
		print = 0;
		if(!daemonize()){
			fprintf(stderr, "Failed to daemonize\n");
			return 1;
		}
	}

	if(print){
		printf("Will print additional information\n");
	}

	ndd_process_file();
	

	for(int i = 0; i < filters_count; i++){
		ndd_free_filter(filters[i], delete);
	}
	for(int i = 0; i < active_filters_count; i++){
		ndd_free_activef(active_filters);
	}

	if(file_count > 1){
		for(int i = 0; i < file_count; i++){
			free(nfcapd_files[i]);
		}
	}else{
		free(nfcapd_current);
	}

	free(filters);
	free(active_filters);
	return 0;
}

