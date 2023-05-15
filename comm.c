#include "comm.h"

void *ndd_manage_io(){
	//Failed to create logs dir, abort
	if(mkdir("./logs/", 0777) && errno != EEXIST){
		fprintf(stderr, "Failed to create logs dir - %s\n", strerror(errno));
		logging = 0;
		return NULL;
	}
	
	FILE *normal = fopen("./logs/ndd.logs", "a");
	FILE *err = fopen("./logs/ndd.err", "a");
	FILE *stats;

	int normal_written = 0;
	int err_written = 0;

	char str[STRING_MAX];
	strcpy(str, "######------------------######\n      New run ");
	char run[11];
	strncpy(run, filters[1]->db_table + 3, 10);
	strcat(str, run);
	strcat(str, "\n");

	fprintf(normal, "%s", str);
	fflush(normal);
	fprintf(err, "%s", str);
	fflush(err);

	int time_since_last_stats = 0;

	while(comm_stop){
		sleep(1);
		//Write all comm messages into log files
		while(comm_bot != NULL){
			//reached last comm message => lock
			if(comm_bot == comm_top)
				pthread_mutex_lock(&comm_lock);

			char tstr[20];
			strftime(tstr, 20, "%Y-%m-%d %H:%M:%S", localtime(&comm_bot->time));

			//check for message type
			if(comm_bot->type == ERROR_MESSAGE){
				if(comm_bot->filter_id > 0)	
					fprintf(err, "%s | F#%d => %s", tstr, comm_bot->filter_id, comm_bot->message);
				else
					fprintf(err, "%s | %s", tstr, comm_bot->message);
				err_written++;
			}
			//error messages are written into normal log and error log
			if(comm_bot->filter_id > 0)
				fprintf(normal, "%s | F#%d => %s", tstr, comm_bot->filter_id, comm_bot->message);
			else
				fprintf(normal, "%s | %s", tstr, comm_bot->message);
			ndd_free_comm(comm_bot);
			
			//finished writing every comm message
			if(comm_bot == NULL)
				pthread_mutex_unlock(&comm_lock);

			normal_written++;
		}


		time_since_last_stats++;
		if(time_since_last_stats >= 300)
			write_stats = 1;
		//Write current state of filters into stats file
		if(write_stats){
			stats = fopen("./logs/ndd.stats", "w");
			if(stats){
				time_since_last_stats = 0;
				time_t stat_time = time(NULL);
				fprintf(stats, "Current filter stats - %s", asctime(localtime(&stat_time)));
				write_stats = 0;
				fprintf(stats, "----------------------------------------\n");
				fprintf(stats, "Total number of filters - %d\n", filters_count-1);
				fprintf(stats, "Current number of active-filters - %d\n", active_filters_count);
				for(int i = 0; i < filters_count; i++){
					ndd_print_filter_info(filters[i], i, stats, 'f');
				}
				ndd_print_active_filters(stats);
				fflush(stats);
				fclose(stats);
			}
		}


		if(err_written){
			fflush(err);
			err_written = 0;
		}
		if(normal_written){
			fflush(normal);
			normal_written = 0;
		}
	}


	time_t tm = time(NULL);
	char tstr[20];
	strftime(tstr, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm));
	
	fprintf(normal, "%s | IO end\n", tstr);
	fflush(normal);

	if(print)
		printf("IO end\n");

	fclose(normal);
	fclose(err);

	return NULL;
}

