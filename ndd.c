
#include <libnf.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <pthread.h>


struct Ndd_rec_t{
	lnf_brec1_t brec;
	uint8_t tcp_flags;

	int processed;
	Ndd_rec_t *next;
	Ndd_rec_t *prev;
};

#define FILTER "src port 53"
#define BASELINE_WINDOW 300 //[s]
#define MAX_NEWEST_CUTOFF 20
#define COEFFICIENT 300

int ndd_find_attack_pattern(uint64_t file_times[], int times_count, int filter_id, uint64_t threshold);

void ndd_init_rec(Ndd_rec_t **rec, Ndd_rec_t *last){
	Ndd_rec_t *r = malloc(sizeof(Ndd_rec_t));
        if(r){
		memset(&r->brec, 0, sizeof(lnf_brec1_t));

		r->tcp_flags = 0;
        r->processed = 0;
		r->next = NULL;
		r->prev = NULL;
        if(last){
            last->next = r;
			r->prev = last;
		}

        *rec = r;
        }
}

void ndd_free_rec(Ndd_rec_t *rec, Ndd_rec_t **first){
	Ndd_rec_t *r = rec;
	if(r){
		if(r->next){
			*first = r->next;
	}else{
		*first = NULL;
	}

	free(r);
	}
}

void ndd_free_rec_processed(Ndd_rec_t *rec, Ndd_rec_t **first){	
        Ndd_rec_t *next;
	while(rec){
		if(rec->processed){
			if(rec->next)
				next = rec->next;
			else
				next = NULL;
			free(rec);
			rec = next;
                }else{
                        *first = rec;
                        break;
                }
        }
        if(rec == NULL){
                *first = NULL;
	}
}

int ndd_clear_old_rec(Ndd_rec_t **r, uint64_t cutoff){
	int removed = 0;
	Ndd_rec_t *tmp;

	while((*r)->brec.first < cutoff){
		tmp = (*r);
		if(!(*r)->next)
			(*r) = NULL;
		else
			(*r) = (*r)->next;
		free(tmp);
		removed++;
	}

	return removed;
}

void ndd_assemble_filepath(char path[], char *filter_name, uint64_t time, int time_index){
	char file_time[11];
	snprintf(file_time, 11, "%"PRIu64, time);
	strcpy(path, "./datasets/");
	strcat(path, filter_name);
	strcat(path, "/ndd-");
	char time_index_converted = time_index > 9 ? time_index + '7' : time_index + '0';
	if(time_index > 35)
	time_index_converted = time_index + '7' + 6;
	strncat(path, &time_index_converted, 1);
	strcat(path, ".");
	strcat(path, file_time);
}

int ndd_write_to_new_file(Ndd_rec_t *r, int filter_id, uint64_t new_time, uint64_t old_time, int time_index){
	int removed = 0;
	Ndd_filter_t *f = filters[filter_id];
	Ndd_rec_t *a = r->prev;
	r->prev = NULL;
	Ndd_rec_t *b;
	lnf_file_t *file;
	lnf_rec_t *rec;

	if(old_time){
			//remove file older than dataset_window
			char old_path[STRING_MAX];
			ndd_assemble_filepath(old_path, f->db_table, old_time, time_index);
			remove(old_path);
			printf("Tried to remove |%s|\n", old_path);
	}

	//create new file
	char new_path[STRING_MAX];
	ndd_assemble_filepath(new_path, f->db_table, new_time, time_index);

	if(lnf_open(&file, new_path, LNF_WRITE, NULL) != LNF_OK){
			fprintf(stderr, "Failed to open file %s\n", new_path);
			return -1;
	}

	lnf_rec_init(&rec);

	while(a){
		lnf_rec_fset(rec, LNF_FLD_BREC1, &a->brec);
		lnf_rec_fset(rec, LNF_FLD_TCP_FLAGS, &a->tcp_flags);

		b = a;
		a = a->prev;
		free(b);
		removed++;

		if(lnf_write(file, rec) != LNF_OK){
				fprintf(stderr, "Failed to write record %d\n", removed);
		}
	}

	lnf_rec_free(rec);
	lnf_close(file);

	return removed;
}


void ndd_print_rec(Ndd_rec_t *first, int id, int process){
        Ndd_rec_t *r = first;
        int i = 1;
        printf("----------------------------------------\n");
        printf("Recs for filter #%d : \n", id);
        while(r){
		if(!r->processed)
                	i++;
                i++;
		if(process)
			r->processed = 1;
                r = r->next;
        }
}

int stop = 1;

void *ndd_process_filter_stream(void *p){
	//Get filter information
	int *id = (int *)p;
	Ndd_filter_t *f = filters[*id];
	
	Ndd_rec_t **new = f->stream;
	Ndd_rec_t *old = NULL;

	//Bytes
	uint64_t bts[BASELINE_WINDOW];
	memset(bts, 0, BASELINE_WINDOW*sizeof(uint64_t));
	uint64_t bts_sum = 0;
	uint64_t bts_baseline = 0;
	uint64_t bps = 0;

	//Packets
	uint64_t pks[BASELINE_WINDOW];
	memset(pks, 0, BASELINE_WINDOW*sizeof(uint64_t));
	uint64_t pks_sum = 0;
	uint64_t pks_baseline = 0;
	uint64_t pps = 0;

	//timestamp of newest flow recieved
	uint64_t newest = 0;
	//index of flow with current newest time
	int nid = 0;
	//index of current flow
	int cid = 0;

	//number of successfull inserts into db
	int successful_insert = 0;
	//number of failed inserts into db
	int failed_insert = 0;
	//number of seconds since previous insert
	int sec_prev_insert = 0;

	//information of current flow
	uint64_t ftime = 0;
	uint64_t bytes = 0;
	uint64_t packets = 0;

	//variables used for attack detection
	uint64_t prev_baseline_limit = 0;
	int window_filled = 0;
	int increase_insert = 0;

	//information
	int values_count = 0;
	for(int i = 0; i < col_count; i++){
		if(f->db_columns[i])
			values_count++;
	}
	uint64_t values_to_insert[values_count];

	int chunks = 0;
	uint64_t file_times [f->dataset_chunks];
	memset(file_times, 0, f->dataset_chunks*sizeof(uint64_t));
	int time_index = 0;
	int records_inserted [f->dataset_chunks];
	
	while(f->stream){
		//lock stream
		pthread_mutex_lock(&f->stream_lock);
		
		//KEEP FOR X SECS
		if((*new) == NULL){
			//there are no records
			pthread_mutex_unlock(&f->stream_lock);
			sleep(1);
			continue;
		}

		if(!(*new)->processed){
			;
		}else if((*new)->next){
			(*new) = (*new)->next;
		}else{
			pthread_mutex_unlock(&f->stream_lock);
			usleep(5000);
			continue;
		}

		if(!old){
			old = (*new);
			printf("Old je %p\n", old);
		}

		//get information from rec
		ftime = (*new)->brec.first;
		bytes = (*new)->brec.bytes;
		packets = (*new)->brec.pkts;
		(*new)->processed = 1;
		
		//unlock stream mutex
		pthread_mutex_unlock(&f->stream_lock);

		//total number of bytes send in current baseline window
		bts_sum += bytes;
		
		//total number of packets send in current baseline window
		pks_sum += packets;

		//remove ms
		ftime = ftime / 1000;

		//first time
		if(newest == 0)
				newest = ftime;

		//calculate index to window
		cid = (ftime - newest) + nid;
		//correct index to within bounds
		cid = cid < 0 ? cid + f->baseline_window : cid >= f->baseline_window ? cid - f->baseline_window : cid;

		//new newest time
		if(newest < ftime){
				int dif = ftime - newest;
				if(dif < f->max_newest_cutoff){
					//move in time
					sec_prev_insert += dif;
					newest = ftime;

					//remove records older than <current-dataset_window ; current>
					//uint64_t cutoff = (newest - (uint64_t)f->dataset_window) * 1000;
					//f->stream_elements -= ndd_clear_old_rec(&old, cutoff);
					chunks++;
					//dataset creation
					if(chunks >= (f->dataset_window/f->dataset_chunks)){
						time_index++;
						time_index = time_index >= f->dataset_chunks ? 0 : time_index;
						uint64_t old_time = file_times[time_index];
							file_times[time_index] = (uint64_t)time(NULL);
						
						int removed =  ndd_write_to_new_file((*new), *id, file_times[time_index], old_time, time_index);
						records_inserted[time_index] = removed;

						pthread_mutex_lock(&f->stream_lock);
						f->stream_elements -= removed;
						pthread_mutex_unlock(&f->stream_lock);
						
						chunks = 0;
					}

					//clear oldest information
					for(int j = 1; j <= dif; j++){
							int index = nid + j;
							//correct index to within bounds
							index = index >= f->baseline_window ? index - f->baseline_window : index;

							bts_sum -= bts[index];
							bts[index] = 0;

							pks_sum -= pks[index];
							pks[index] = 0;
					}
					nid = cid;
					increase_insert = 1;
				}else{
					//current flow is much newer => add it to current second
					cid = nid;
				}
		}	


		if(cid < 0){
			//flow is older than baseline window => add to oldest second
			if(nid == (f->baseline_window-1)){
				bts[0] += bytes;
				pks[0] += packets;
			}else{
				bts[nid+1] += bytes;
				pks[nid+1] += packets;
			}
		}else{
			//add bytes to specific second
			bts[cid] += bytes;
			pks[cid] += packets;
		}

		//check which value are to be computed, based on list of columns in config
		if(f->db_columns[0] || f->db_columns[1]){
                	//compute new baseline for bytes per second
                	bps = bts_sum / f->baseline_window;
                	bts_baseline = (bts_baseline + bps * f->coefficient) / (f->coefficient + 1);
		}

		if(f->db_columns[2] || f->db_columns[3]){
                	//compute new baseline for packets per second
                	pps = pks_sum / f->baseline_window;
                	pks_baseline = (pks_baseline + pps * f->coefficient) / (f->coefficient + 1);
		}


		//check for substantial increase in baseline
		if(window_filled){
			if(bts_baseline > prev_baseline_limit){
				if(increase_insert){
					uint64_t prev_baseline = prev_baseline_limit / f->max_baseline_increase;
					if(ndd_db_insert_detection(f->db_table, newest, bts_baseline, prev_baseline)){
						//substantial increase detected => information inserted into db	
						increase_insert = 0;
					}
					ndd_find_attack_pattern(file_times, f->dataset_chunks, *id, prev_baseline_limit);
				}
			}
		}

		if(sec_prev_insert >= f->db_insert_interval){
			int c = 0;
                	//fill array with values to be stored in db
			//needs to be filled in specific order
			for(int i = 0; i < col_count; i++){
				if(f->db_columns[i]){
					switch(i){
						case 0 : {values_to_insert[c] = bts_baseline; break;}
						case 1 : {values_to_insert[c] = bps; break;}
						case 2 : {values_to_insert[c] = pks_baseline; break;}
						case 3 : {values_to_insert[c] = pps; break;}
					}
					c++;
				}
			}
			//try to insert
			if(ndd_db_insert(newest, values_to_insert, f->db_table, f->db_columns)){
				if(!window_filled){
					//if baseline_window is filled start checking increases in baseline
					window_filled = successful_insert * f->db_insert_interval > f->baseline_window ? 1 : 0;
				}
				successful_insert++;
				prev_baseline_limit = bts_baseline * f->max_baseline_increase;
				//printf("Filter #%d => %d(-%d): bt_Baseline inserted - %lu | pk_Baseline inserted %lu |records ready - %d|\n", (*id), successful_insert, failed_insert, bts_baseline, pks_baseline, f->stream_elements_ready);
			}else{
				failed_insert++;
			}
			sec_prev_insert = 0;
		}
	}

	return NULL;
}


int process_file(){
	lnf_file_t *filep;
	lnf_rec_t *rec;

	int loopread = 1;

	if(lnf_open(&filep, nfcapd_current, LNF_READ | loopread ? LNF_READ_LOOP : 0, NULL) != LNF_OK){
		fprintf(stderr, "Failed to open file %s\n", nfcapd_current);
		exit(1);
	}

	lnf_rec_init(&rec);

	int ret;

	uint64_t bytes;
        
	Ndd_rec_t *first[filters_count];
	Ndd_rec_t *last[filters_count];

	pthread_t th[filters_count];

	int is[filters_count];
	

        for(int i = 0; i < filters_count; i++){
			first[i] = NULL;
			last[i] = NULL;
		if(i > 0){
			filters[i]->stream = &first[i];
			is[i] = i;
			if(pthread_create(&th[i], NULL, ndd_process_filter_stream, &is[i])){
				fprintf(stderr, "Failed to create thread\n");
			}
		}
        }
	
	while(stop){
                ret = lnf_read(filep, rec);

                if(ret == LNF_EOF){
                        break;
                }

                for(int i = 1; i < filters_count; i++){
					if(lnf_filter_match(filters[i]->filter, rec)){
						lnf_rec_fget(rec, LNF_FLD_DOCTETS, &bytes);
						if(bytes == 0)
							break;
				pthread_mutex_lock(&filters[i]->stream_lock);
                                
				if(first[i] == NULL)
					last[i] = NULL;
				//Create new and append
				ndd_init_rec(&last[i], last[i]);
				if(first[i] == NULL)
					first[i] = last[i];
				
				lnf_rec_fget(rec, LNF_FLD_BREC1, &last[i]->brec);
				lnf_rec_fget(rec, LNF_FLD_TCP_FLAGS, &last[i]->tcp_flags);
                                
				filters[i]->stream_elements++;

				pthread_mutex_unlock(&filters[i]->stream_lock);
			}
                }
        }
	
	int j = 1;
	while(1){
		filters[j]->stream_elements = 0; //---
		if(filters[j]->stream_elements == 0){
			filters[j]->stream = NULL;
			ndd_clear_old_rec(&first[j], 999999999999); //---
			ndd_free_rec_processed(first[j], &first[j]);
			if((j+1) < filters_count)
				j++;
			else
				break;
		}			
		sleep(1);
	}

	for(int i = 1; i < filters_count; i++){
		if(pthread_join(th[i], NULL)){
			fprintf(stderr, "error\n");
		}
	}

	for(int i = 1; i < filters_count ;i++){
		ndd_print_rec(first[i], i, 1);
		ndd_free_rec_processed(first[i], &first[i]);
	}

	lnf_rec_free(rec);
	lnf_close(filep);

	return 0;
}

void ndd_tcp_flags_decode(char on[], char off[], uint8_t flags, int *on_count){
	int result = 0;
	int index = 0;
	(*on_count) = 0;
	char cflags[] = {'F', 'S', 'R', 'P', 'A', 'U'};
	strcpy(on, "");
	strcpy(off, "");
	for(int bit = 1; bit < 64; bit = bit << 1){ 
		result = flags & bit;
		if(result > 0){
			strncat(on, &cflags[index], 1);
			(*on_count)++;
		}else{
			strncat(off, &cflags[index], 1);
		}
		index++;
	}
	
}

int ndd_add_active_filter(lnf_filter_t *f){
	pthread_mutex_lock(&active_filters_lock);
	if(active_filters_allocated < (active_filters_count+1)){
		lnf_filter_t **tmp;
		lnf_filter_t **tmp2;
		tmp = malloc(sizeof(lnf_filter_t *) * (active_filters_allocated + 10));
		for(int i = 0; i < active_filters_count; i++){
			tmp[i] = active_filters[i];
		}	
		tmp2 = active_filters;
		active_filters = tmp;
		free(tmp2);

		active_filters_allocated += 10;
		active_filters[active_filters_count] = f;
		active_filters_count++;
	}else{
		active_filters[active_filters_count] = f;
		active_filters_count++;
	}	
	pthread_mutex_unlock(&active_filters_lock);
	return 0;
}

#define LLUI long long unsigned int

int ndd_find_attack_pattern(uint64_t file_times[], int file_count, int filter_id, uint64_t threshold){
	lnf_rec_t *rec;
	Ndd_filter_t *f = filters[filter_id];
	lnf_mem_t *mem_original_dataset;

	int records = 0;
	uint64_t threshold2 = threshold;
	int thstep = f->thstep;

	lnf_rec_init(&rec);
	lnf_mem_init(&mem_original_dataset);

	
	// --- 1 ---
	//original dataset memory configuration
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_SRCADDR, LNF_AGGR_KEY, 32, 128);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_DSTADDR, LNF_AGGR_KEY, 32, 128);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_PROT, LNF_AGGR_KEY, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_SRCPORT, LNF_AGGR_KEY, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_DSTPORT, LNF_AGGR_KEY, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_TCP_FLAGS, LNF_AGGR_KEY, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_DOCTETS, LNF_AGGR_SUM, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_DPKTS, LNF_AGGR_SUM, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_FIRST, LNF_AGGR_MIN, 0, 0);
	lnf_mem_fadd(mem_original_dataset, LNF_FLD_LAST, LNF_AGGR_MAX, 0, 0);

	//read whole dataset
	for(int i = 0; i < file_count; i++){
		lnf_file_t *file;

		char path[STRING_MAX];
        ndd_assemble_filepath(path, f->db_table, file_times[i], i);

		if(lnf_open(&file, path, LNF_READ, NULL) != LNF_OK){
			fprintf(stderr, "Failed to open dataset file %s\n", path);
			return -1;
		}

		while(lnf_read(file, rec) != LNF_EOF){
			lnf_mem_write(mem_original_dataset, rec);
			records++;
		}

		lnf_close(file);	
	}

	// --- 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 ---
	while(1){
		//get active filters
		pthread_mutex_lock(&active_filters_lock);
		int act_filters_count = active_filters_count;
		lnf_filter_t *act_filters[act_filters_count];
		for(int i = 0; i < act_filters_count; i++){
			act_filters[i] = active_filters[i];
		}
		pthread_mutex_unlock(&active_filters_lock);
		
		int aggr_filters_count = 0;
		int filter_candidate[items_count];
		memset(filter_candidate, 0, sizeof(int)*items_count);
		char filter_candidate_text[items_count][STRING_MAX];
		lnf_filter_t *aggr_filters[items_count];
		// --- 2 + 3 + 4 + 5 + 6 + 7 + 8 ---
		for(int i = 0; i < items_count; i++){
			if(f->eval_items[i] == 0)
				break;
			
			//filter and aggregace dataset
			lnf_mem_t *mem_altered_dataset;
			lnf_mem_init(&mem_altered_dataset);

			//--- 4 + 5 + 8 ---
			//set aggregation key based on eval_items information
			if(strstr(items_text[i], "ip"))
				lnf_mem_fadd(mem_altered_dataset, items[f->eval_items[i]], LNF_AGGR_KEY, 32, 128);
			else
				lnf_mem_fadd(mem_altered_dataset, items[f->eval_items[i]], LNF_AGGR_KEY, 0, 0);

			//set additional aggregation information
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_FIRST, LNF_AGGR_MIN, 0, 0);
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_LAST, LNF_AGGR_MAX, 0, 0);
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DOCTETS, LNF_AGGR_SUM | LNF_SORT_DESC, 0, 0);
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DPKTS, LNF_AGGR_SUM, 0, 0);
			
			lnf_mem_cursor_t *csr;
			lnf_mem_first_c(mem_original_dataset, &csr);
			
			int passed = 1;
			int active_reject = 0;
			uint64_t dataset_baseline = 0;
			uint64_t bytes = 0;
			while(csr != NULL){
				lnf_mem_read_c(mem_original_dataset, csr, rec);
				lnf_mem_next_c(mem_original_dataset, &csr);
				passed = 1;

				//records REJECTED based on global active_filters
				for(int j = 0; j < act_filters_count; j++){
					if(lnf_filter_match(act_filters[j], rec)){		
						passed = 0;
						active_reject++;
						break;
					}
				}
				if(!passed)
					continue;

				//--- 3 ---
				//records SELECTED based on aggr_filter
				for(int j = 0; j < aggr_filters_count; j++){
					if(!lnf_filter_match(aggr_filters[j], rec)){
						passed = 0;
						break;
					}
				}

				if(passed){
					lnf_mem_write(mem_altered_dataset, rec);
				}
				lnf_rec_fget(rec, LNF_FLD_DOCTETS, &bytes);
				dataset_baseline += bytes;
			}

			dataset_baseline = dataset_baseline / f->dataset_window;
			//--- 2 ---
			if(dataset_baseline <= threshold){
				//EXIT + free everything
				lnf_rec_free(rec);
				lnf_mem_free(mem_original_dataset);
				lnf_mem_free(mem_altered_dataset);
				return 0;
			}
				
			
			lnf_brec1_t brec;
			uint8_t tcp_flags = 0;
			lnf_mem_first_c(mem_altered_dataset, &csr);

			uint64_t first;
			uint64_t last;
			uint64_t top_current = 0;

			records = 0;
			//how many top records are selected
			int top_x = 1;
			int index = 0;
			dataset_baseline = 0;
			while(csr != NULL){
				lnf_mem_read_c(mem_altered_dataset, csr, rec);
				if(records < top_x){
					//get number of bytes from top record and transform it into current[bps]
					lnf_rec_fget(rec, LNF_FLD_FIRST, &first);
                    lnf_rec_fget(rec, LNF_FLD_LAST, &last);
					lnf_rec_fget(rec, LNF_FLD_DOCTETS, &top_current);
					uint64_t duration = (last - first) / 1000;
                    duration = duration > 0 ? duration : 1;
                    top_current = top_current / duration;

					//--- 6 ---
					if(top_current > threshold2) {
						//add to filter_candidate + make aggr_filter
						//--- 7 ---
						lnf_rec_fget(rec, LNF_FLD_BREC1, &brec);
						char filter_text[STRING_MAX]; 
						switch(items[f->eval_items[i]]){
							case LNF_FLD_SRCADDR : {
								index = 1;
								char buf[INET6_ADDRSTRLEN];
								inet_ntop(AF_INET6, &brec.srcaddr, buf, INET6_ADDRSTRLEN);
								strcpy(filter_text, "src ip ");
								strcat(filter_text, buf);
								break;		       
							}
							case LNF_FLD_DSTADDR : {
								index = 2;
								char buf[INET6_ADDRSTRLEN];
								inet_ntop(AF_INET6, &brec.dstaddr, buf, INET6_ADDRSTRLEN);
								strcpy(filter_text, "dst ip ");
								strcat(filter_text, buf);
								break;		      
							}
							case LNF_FLD_PROT : {
								index = 3;
								char buf[STRING_MAX];
								sprintf(buf, "%d", brec.prot);
								strcpy(filter_text, "proto ");
								strcat(filter_text, buf);
								break;
							}
							case LNF_FLD_SRCPORT : {
								index = 4;
								char buf[STRING_MAX];
								sprintf(buf, "%d", brec.srcport);
								strcpy(filter_text, "src port ");
								strcat(filter_text, buf);
								break;		       
							}
							case LNF_FLD_DSTPORT : {
								index = 5;
								char buf[STRING_MAX];
								sprintf(buf, "%d", brec.dstport);
								strcpy(filter_text, "dst port ");
								strcat(filter_text, buf);
								break;		       
							}
							case LNF_FLD_TCP_FLAGS : {
								index = 6;
								uint8_t flags = 0;
								lnf_rec_fget(rec, LNF_FLD_TCP_FLAGS, &flags);
								char on[10];
								char off[10];
								int on_count = 0;
								ndd_tcp_flags_decode(on, off, flags, &on_count);
								
								strcpy(filter_text, "(");
								if(on_count > 0){
									strcat(filter_text, "flags ");
									strcat(filter_text, on);
									if(on_count < 6)
										strcat(filter_text, " and ");	
								}
								if(on_count < 6){
									strcat(filter_text, "not flags ");
									strcat(filter_text, off);
								}
								strcat(filter_text, ")");
								break;			 
							}
						}
						if(filter_candidate[index]){
							strcat(filter_candidate_text[index], " OR ");
							strcat(filter_candidate_text[index], filter_text);
						}else{
							strcpy(filter_candidate_text[index], filter_text);
						}
						filter_candidate[index]++;
					}
				}			

				if(records == 0){
					lnf_rec_fget(rec, LNF_FLD_FIRST, &first);
					lnf_rec_fget(rec, LNF_FLD_LAST, &last);
					lnf_rec_fget(rec, LNF_FLD_DOCTETS, &top_current);


					uint64_t duration = (last - first) / 1000;
					duration = duration > 0 ? duration : 1;
					top_current = top_current / duration;
				}

				lnf_rec_fget(rec, LNF_FLD_BREC1, &brec);
				
				dataset_baseline += brec.bytes;

				if(records < 3){
					char sbuf[INET6_ADDRSTRLEN];
					char dbuf[INET6_ADDRSTRLEN];

					//lnf_rec_fget(rec, LNF_FLD_BREC1, &brec);
					lnf_rec_fget(rec, LNF_FLD_TCP_FLAGS, &tcp_flags);

					inet_ntop(AF_INET6, &brec.srcaddr, sbuf, INET6_ADDRSTRLEN);
					inet_ntop(AF_INET6, &brec.dstaddr, dbuf, INET6_ADDRSTRLEN);

				}
				records++;
				lnf_mem_next_c(mem_altered_dataset, &csr);
			}

			if(index){
				if(filter_candidate[index] > 1){
					char filter_text[STRING_MAX];
					strcpy(filter_text, "(");
					strcat(filter_text, filter_candidate_text[index]);
					strcat(filter_text, ")");
					strcpy(filter_candidate_text[index], filter_text);
				}

				int con;
				lnf_filter_t *flt;
				if((con = lnf_filter_init_v1(&flt, filter_candidate_text[index])) != LNF_OK){
						fprintf(stderr, "Failed to initialise libnf filter (%d): \"%s\"\n", con, filter_candidate_text[index]);
				}else{
					aggr_filters[aggr_filters_count] = flt;
					aggr_filters_count++;
				}
			}
			lnf_mem_free(mem_altered_dataset);
		}
		//end of eval-items loop

		for(int i = 0; i < aggr_filters_count; i++){
			lnf_filter_free(aggr_filters[i]);
		}

		char found_pattern[STRING_MAX];
		int first = 1;
		int required_items_counted = 0;
		int matching_filter_candidates_counted = 0;
		//--- 9 ---
		for(int i = 0; i < items_count; i++){
			if(f->required_items[i] == 0)
				break;
			if(filter_candidate[f->required_items[i]]){
				if(first){
					first = 0;
					strcpy(found_pattern, filter_candidate_text[f->required_items[i]]);
				}else{
					strcat(found_pattern, " AND ");
					strcat(found_pattern, filter_candidate_text[f->required_items[i]]);
				}
				matching_filter_candidates_counted++;
			}
			required_items_counted++;
		}

		if(required_items_counted == matching_filter_candidates_counted){
			//--- 10 ---
			int con;
			lnf_filter_t *flt;
			if((con = lnf_filter_init_v1(&flt, found_pattern)) != LNF_OK){
				fprintf(stderr, "Failed to initialise libnf filter (%d): \"%s\"\n", con, found_pattern);
				continue;
			}else{
				ndd_add_active_filter(flt);
			}
		}else{
			//--- 11 ---
			thstep--;
			//--- 12 ---
			if(thstep == 0){
				break;
			}
			threshold2 = (threshold / f->thsteps) * thstep;
		}
	}

	// kontrola jestli je potřeba ještě něco freeovat

	lnf_rec_free(rec);
	lnf_mem_free(mem_original_dataset);

	return records;
}


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

