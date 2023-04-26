
#include "comm.h"

void ndd_init_comm(ndd_comm_t **c){
	ndd_comm_t *m = malloc(sizeof(ndd_comm_t));
	if(m){
		(*c) = m;
		(*c)->type = -1;
		(*c)->message = NULL;
		(*c)->next = NULL;
		if(comm_bot == NULL){
			comm_bot = (*c);
			comm_top = (*c);
		}else{
			comm_top->next = (*c);
			comm_top = (*c);
		}
	}
}

void ndd_clear_comm(ndd_comm_t *c){
	if(comm_bot == c)
		comm_bot = c->next;
	free(c->message);
	free(c);
	if(comm_bot == NULL)
		comm_top = NULL;
}

void ndd_fill_comm(char *string, int type){
	ndd_comm_t *c = NULL;

	pthread_mutex_lock(&comm_lock);
	ndd_init_comm(&c);

	c->message = strdup(string);
	c->type = type;
	c->time = time(NULL);
        pthread_mutex_unlock(&comm_lock);
}



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

	int write_stats = 1;

	char str[STRING_MAX];
        strcpy(str, "######------------------######\n      New run ");
        char t[11];
	strncpy(t, filters[1]->db_table + 3, 10);
	strcat(str, t);
	strcat(str, "\n");

	fprintf(normal, "%s", str);
	fflush(normal);
	fprintf(err, "%s", str);
	fflush(err);

	while(comm_stop){
		sleep(1);
		//Write all comm messages into log files
		while(comm_bot != NULL){
			//reached last comm message => lock
			if(comm_bot == comm_top)
				pthread_mutex_lock(&comm_lock);

			char tstr[23];
			strftime(tstr, 20, "%Y-%m-%d %H:%M:%S", localtime(&comm_bot->time));
			strcat(tstr, " | ");

			//check for message type
			if(comm_bot->type == ERROR_MESSAGE){
				fprintf(err, tstr);	
				fprintf(err, comm_bot->message);
				err_written++;
			}
			//error messages are written into normal log and error log
			fprintf(normal, tstr);
			fprintf(normal, comm_bot->message);
			ndd_clear_comm(comm_bot);
			
			//finished writing every comm message
			if(comm_bot == NULL)
				pthread_mutex_unlock(&comm_lock);

			normal_written++;
		}


		//Write current state of filters into stats file
		if(write_stats){
			stats = fopen("./logs/ndd.stats", "w");
			if(stats){
				time_t stat_time = time(NULL);
				fprintf(stats, "Current filter stats - %s", asctime(localtime(&stat_time)));
				write_stats = 0;
				for(int i = 0; i < filters_count; i++){
					ndd_print_filter_info(filters[i], i, stats, 'f');
				}
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
	char tstr[23];
        strftime(tstr, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm));
        strcat(tstr, " | ");
	
	fprintf(normal, "%sIO end\n", tstr);
	fflush(normal);

	if(print)
		printf("IO end\n");

	fclose(normal);
	fclose(err);

	return NULL;
}

