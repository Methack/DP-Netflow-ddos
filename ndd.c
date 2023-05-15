#include "ndd.h"

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

int ndd_write_to_new_file(ndd_rec_t *r, int filter_id, uint64_t new_time, uint64_t old_time, int time_index){
	int removed = 0;
	ndd_filter_t *f = filters[filter_id];
	ndd_rec_t *a = r->prev;
	r->prev = NULL;
	ndd_rec_t *b;
	lnf_file_t *file;
	lnf_rec_t *rec;
        
	//remove file older than dataset_window
	char old_path[STRING_MAX];
	ndd_assemble_filepath(old_path, f->db_table, old_time, time_index);
	remove(old_path);
	
	//create new file
	char new_path[STRING_MAX];
	ndd_assemble_filepath(new_path, f->db_table, new_time, time_index);

	if(lnf_open(&file, new_path, LNF_WRITE, NULL) != LNF_OK){
		char msg[STRING_MAX*2];
		sprintf(msg, "Failed to open file %s\n", new_path);
		if(logging)
			ndd_fill_comm(msg, ERROR_MESSAGE, filter_id);
		fprintf(stderr, "F#%d => %s", filter_id, msg);
		
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
			char msg[STRING_MAX];
			sprintf(msg, "Failed to write record %d\n", removed);
			if(logging)
			ndd_fill_comm(msg, ERROR_MESSAGE, filter_id);
			fprintf(stderr, "F#%d => %s", filter_id, msg);
		}
	}

	lnf_rec_free(rec);
	lnf_close(file);

	return removed;
}

int waiting = 0;
int main_update = 0;

void *ndd_process_filter_stream(void *p){
	//Get filter information
	int *id = (int *)p;
	ndd_filter_t *f = filters[*id];
	
	ndd_rec_t **new = f->stream;

	//Bytes
	uint64_t bts[f->baseline_window];
	memset(bts, 0, f->baseline_window*sizeof(uint64_t));
	uint64_t bts_sum = 0;
	uint64_t bts_baseline = 0;
	uint64_t bps = 0;

	//Packets
	uint64_t pks[f->baseline_window];
	memset(pks, 0, f->baseline_window*sizeof(uint64_t));
	uint64_t pks_sum = 0;
	uint64_t pks_baseline = 0;
	uint64_t pps = 0;

	int update_baseline = 1;

	//current bytes
	uint64_t current_b_arr[f->dataset_window];
	memset(current_b_arr, 0, f->dataset_window*sizeof(uint64_t));
	uint64_t current_b_sum = 0;
	uint64_t current_b = 0;
	uint64_t prev_current_b = 0;

	//current packets
	uint64_t current_p_arr[f->dataset_window];
	memset(current_p_arr, 0, f->dataset_window*sizeof(uint64_t));
	uint64_t current_p_sum = 0;
	uint64_t current_p = 0;
	uint64_t prev_current_p = 0;

	int current_index = 0;

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
	uint64_t prev_b_baseline_limit = 0;
	uint64_t prev_p_baseline_limit = 0;
	int window_filled = 0;
	int increase_insert = 0;

	int older_cutoff = 0;

	//information
	int values_count = 0;
	for(int i = 0; i < col_count; i++){
		if(f->db_columns[i])
			values_count++;
	}
	uint64_t values_to_insert[values_count];
	
	//datasets
	int chunks = 0;
	uint64_t file_times [f->dataset_chunks];
	memset(file_times, 0, f->dataset_chunks*sizeof(uint64_t));
	int time_index = 0;
	int records_inserted [f->dataset_chunks];

	//logging
	char msg[STRING_MAX*2];
	while(f->stream){
		if(waiting && !(*new)->next){
			break;
			f->stream_elements = 0;
		}
		
		//lock stream
		pthread_mutex_lock(&f->stream_lock);

		//KEEP FOR X SECS
		if((*new) == NULL){
			//there are no records
			pthread_mutex_unlock(&f->stream_lock);
			usleep(50);
			continue;
		}

		if(!(*new)->processed){
			;
		}else if((*new)->next){
			(*new) = (*new)->next;
		}else{
			pthread_mutex_unlock(&f->stream_lock);
			usleep(50);
			continue;
		}

		//get information from rec
		ftime = (*new)->brec.first;
		bytes = (*new)->brec.bytes;
		packets = (*new)->brec.pkts;
		(*new)->processed = 1;
		
		f->stream_elements--;

		//unlock stream mutex
		pthread_mutex_unlock(&f->stream_lock);

		if(update_baseline){
			//total number of bytes send in current baseline window
			bts_sum += bytes;
		
			//total number of packets send in current baseline window
			pks_sum += packets;
		}

		//currents
		current_b_sum += bytes;
		current_p_sum += packets;

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
			if(dif < f->max_newest_cutoff || older_cutoff > 100){
				older_cutoff = 0;
				//move in time
				sec_prev_insert += dif;
				newest = ftime;

				//current
				current_index = current_index < (f->dataset_window-1) ? current_index + 1 : 0;
				current_b_sum -= current_b_arr[current_index];
				current_b_arr[current_index] = 0;
				current_p_sum -= current_p_arr[current_index];
				current_p_arr[current_index] = 0;

				chunks++;
				increase_insert++;
				//dataset creation
				if(chunks >= (f->dataset_window/f->dataset_chunks)){
					time_index++;
					time_index = time_index >= f->dataset_chunks ? 0 : time_index;
					uint64_t old_time = file_times[time_index];
					file_times[time_index] = (uint64_t)time(NULL);
				
					records_inserted[time_index] =  ndd_write_to_new_file((*new), *id, file_times[time_index], old_time, time_index);

					pthread_mutex_lock(&f->stream_lock);
					//f->stream_elements -= records_inserted[time_index];
					if(print)
						printf("F#%d => New dataset file, records inserted %d, records remaining %d\n", *id, records_inserted[time_index], f->stream_elements);

					pthread_mutex_unlock(&f->stream_lock);

					if(logging){
						if(time_index == 0){
							char num[10];
							int total = 0;
							sprintf(msg, "%d dataset files created |", f->dataset_chunks);
							for(int i = 0; i < f->dataset_chunks; i++){
								snprintf(num, 10, "%d", records_inserted[i]);
								total += records_inserted[i];
								strcat(msg, num);
								strcat(msg, "|");
							}
							strcat(msg, " Records total = ");
							snprintf(num, 10, "%d", total);
							strcat(msg, num);
							strcat(msg, " | Remaining - ");
							snprintf(num, 10, "%d", f->stream_elements);
							strcat(msg, num);
							strcat(msg, "\n");
							ndd_fill_comm(msg, NORMAL_MESSAGE, *id);
						}
					}
					chunks = 0;
				}

				//clear oldest information
				for(int j = 1; j <= dif && update_baseline; j++){
					int index = nid + j;
					//correct index to within bounds
					index = index >= f->baseline_window ? index - f->baseline_window : index;

					bts_sum -= bts[index];
					bts[index] = 0;

					pks_sum -= pks[index];
					pks[index] = 0;
				}
				nid = cid;
			}else{
				//current flow is much newer => add it to current second
				cid = nid;
				//prevent getting stuck in the past
				older_cutoff++;
				if(older_cutoff > 100){
					if(logging)
						ndd_fill_comm("Got stuck in the past\n", ERROR_MESSAGE, *id);
					if(print)
						printf("F#%d => Got stuck in the past\n", *id);
				}
			}
		}


		if(update_baseline){
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

			//compute new baseline for bytes per second
			bps = bts_sum / f->baseline_window;
			bts_baseline = (bts_baseline + bps * f->coefficient) / (f->coefficient + 1);
                
			//compute new baseline for packets per second
			pps = pks_sum / f->baseline_window;
			pks_baseline = (pks_baseline + pps * f->coefficient) / (f->coefficient + 1);
		}

		//fill current arrs
		current_b_arr[current_index] += bytes;
		current_p_arr[current_index] += packets;

		//calculate most recent current
		current_b = current_b_sum / f->dataset_window;
		current_p = current_p_sum / f->dataset_window;

		if(!update_baseline && prev_b_baseline_limit > current_b && prev_p_baseline_limit > current_p){
			update_baseline = 1;
			if(logging)
				ndd_fill_comm("Current is normal => starting baseline calculation\n", ERROR_MESSAGE, *id);
			if(print)
				printf("F#%d => Current is normal => starting baseline calculation\n", *id);
		}

		if((prev_current_b != 0 && (prev_current_b*2) < current_b) || (prev_current_p != 0 && (prev_current_p*2) < current_p)){
			increase_insert = 5;
		}

		//check for substantial increase in baseline
		if(window_filled && increase_insert >= 5 && (prev_b_baseline_limit < current_b || prev_p_baseline_limit < current_p)){
			uint64_t prev_baseline;
			char type;
			uint64_t insert_baseline;
			uint64_t limit;

			if(prev_b_baseline_limit < current_b){
				prev_baseline = prev_b_baseline_limit / f->max_baseline_increase;
				type = 'B';
				insert_baseline = bts_baseline;
				limit = prev_b_baseline_limit;
				prev_current_b = current_b;
				prev_current_p = 0;
			}else{
				prev_baseline = prev_p_baseline_limit / f->max_baseline_increase;
				type = 'p';
				insert_baseline = pks_baseline;
				limit = prev_p_baseline_limit;
				prev_current_p = current_p;
				prev_current_b = 0;
			}
			
			if(ndd_db_insert_detection(f->db_table, newest, insert_baseline, prev_baseline, type)){
				//substantial increase detected => information inserted into db	
				increase_insert = 0;
			}
			//printf("Hodnoty tu jsou baseline %luBps %lupps | Current %luBps %lupps | threshold %luBps %lupps\n", bts_baseline, pks_baseline, current_b, current_p, prev_b_baseline_limit, prev_p_baseline_limit);
			//try to find attack pattern in dataset
			if(ndd_find_attack_pattern(file_times, f->dataset_chunks, *id, limit, (*new), type)){
				if(logging)
					ndd_fill_comm("Found active_filter => stopping baseline calculation\n", ERROR_MESSAGE, *id);
				if(print)
					printf("F#%d => Found active_filter => stopping baseline calculation\n", *id);
				update_baseline = 0;
				main_update = 1;
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
				if(update_baseline){
					prev_b_baseline_limit = bts_baseline * f->max_baseline_increase;
					prev_p_baseline_limit = pks_baseline * f->max_baseline_increase;
				}
				if(logging){
					sprintf(msg, "Inserts %d(failed %d): Threshold B-%lu | p-%lu\n", successful_insert, failed_insert, prev_b_baseline_limit, prev_p_baseline_limit);
					ndd_fill_comm(msg, NORMAL_MESSAGE, *id);
				}
				if(print)
					printf("F#%d => Inserts %d(failed %d): Threshold B-%lu | p-%lu\n", *id, successful_insert, failed_insert, prev_b_baseline_limit, prev_p_baseline_limit);
				
				//if set stop program after number of db insertes
				if(stop_number > 0 && successful_insert >= stop_number)
					stop = 0;
			}else{
				failed_insert++;
				if(logging){
					sprintf(msg, "%d Failed to insert into db\n", failed_insert);
					ndd_fill_comm(msg, ERROR_MESSAGE, *id);
				}
				if(print)
					printf("F#%d => %d Failed to insert into db\n", *id, failed_insert);
					
			}
			sec_prev_insert = 0;
		}
	}
	
	f->stream_elements = 0;

	//clear all dataset files
	char filepath[STRING_MAX];
	for(int i = 0; i < f->dataset_chunks; i++){
		ndd_assemble_filepath(filepath, f->db_table, file_times[i], i);
		remove(filepath);
	}

	return NULL;
}


int ndd_process_file(){
	lnf_file_t *filep;
	lnf_rec_t *rec;

	if(file_count > 1)
		nfcapd_current = nfcapd_files[0];

        if(lnf_open(&filep, nfcapd_current, LNF_READ | loop_read ? LNF_READ_LOOP : 0, NULL) != LNF_OK){
			fprintf(stderr, "Failed to open file %s\n", nfcapd_current);
			exit(1);
	}

	lnf_rec_init(&rec);

	int ret;
	int wait_time;
	uint64_t bytes;
	int read_files = 1;
        
	ndd_rec_t *first[filters_count];
	ndd_rec_t *last[filters_count];

	pthread_t th[filters_count+1];

	int is[filters_count];

	uint64_t filtered = 0;
	uint64_t filtered_sum = 0;
	int skip_rec = 0;
	int check_active = 1;

	uint64_t next_refresh = 0;
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

	if(logging){
		if(pthread_create(&th[filters_count], NULL, ndd_manage_io, NULL)){
			fprintf(stderr, "Failed to create thread\n");
		}
	}

	char msg[STRING_MAX*3];
	while(stop){
		ret = lnf_read(filep, rec);

		if(ret == LNF_EOF){
			//If multiple files exist, open next file in order a continue reading it
			if(file_count > 1){
				lnf_close(filep);
				if(read_files < file_count){
					if(lnf_open(&filep, nfcapd_files[read_files], LNF_READ, NULL) != LNF_OK){
						fprintf(stderr, "Failed to open file %s\n", nfcapd_files[read_files]);
						exit(1);
					}
					if(print)
						printf("Finished reading file %s, proceeding to read file %s\n", nfcapd_files[read_files-1], nfcapd_files[read_files]);
					if(logging){
						sprintf(msg, "Finished reading file %s, proceeding to read file %s\n", nfcapd_files[read_files-1], nfcapd_files[read_files]);
						ndd_fill_comm(msg, NORMAL_MESSAGE, 0);
					}

					read_files++;
					continue;
				}
			}

			//If loop_read is not set, exit when encountering EOF
			if(!loop_read)
				break;
			//If loop_read is set, EOF is error -> try to open file again
			if(logging)
				ndd_fill_comm("Found EOF in nfcapd.current\n", ERROR_MESSAGE, 0);
			wait_time = 1;
			int recover_tries = 0;
			while(1){
				ret = lnf_read(filep, rec);
				if(ret == LNF_EOF){
					sprintf(msg, "Found EOF again (%d), will continue trying after %ds \n", recover_tries, wait_time);
					ndd_fill_comm(msg, ERROR_MESSAGE, 0);
					sleep(wait_time);
					wait_time = wait_time < 128 ? wait_time << 1 : wait_time;
					recover_tries++;
				}else{
					ndd_fill_comm("Managed to recover from EOF, will continue normal operations\n", ERROR_MESSAGE, 0);
					break;
				}
			}
		}

		check_active = 1;
		for(int i = 1; i < filters_count; i++){
			if(lnf_filter_match(filters[i]->filter, rec)){
				if(check_active){
					check_active = 0;
					
					pthread_mutex_lock(&active_filters_lock);
					ndd_activef_t *f = active_filters;
					uint64_t cur = (uint64_t)time(NULL);
					//Filter by current active-filters
					while(f){
						if(f->tstop < cur){
							ndd_remove_old_active_filters();
							break;
						}
						if(lnf_filter_match(f->filter, rec)){
							skip_rec = 1;
							lnf_rec_fget(rec, LNF_FLD_DOCTETS, &filtered);
							f->filtered_bytes += filtered;
							filtered_sum += filtered;
							lnf_rec_fget(rec, LNF_FLD_DPKTS, &filtered);
							f->filtered_packets += filtered;	
							break;
						}
						f = f->next;
					}
					pthread_mutex_unlock(&active_filters_lock);

					//Skip when rec matched with active-filter
					if(skip_rec){
						skip_rec = 0;
						break;
					}
				}

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

				if(last[i]->brec.first > next_refresh || main_update){
					main_update = 0;
					next_refresh = last[i]->brec.first + 30000;
					if(filtered_sum > 0){
						if(print)
							printf("Main filtered %luB in last 30s window with %d active-filters\n", filtered_sum, active_filters_count);
						if(logging){
							sprintf(msg, "Main filtered %luB in last 30s window with %d active-filters\n", filtered_sum, active_filters_count);
						ndd_fill_comm(msg, NORMAL_MESSAGE, 0);
						}
						filtered_sum = 0;
					}
				}
			}
		}
	}
	
	if(logging)
		ndd_fill_comm("Main done\n", NORMAL_MESSAGE, 0);
	if(print)
		printf("Main done\n");
	waiting = 1;
	for(int j = 1; j < filters_count; j++){
		if(!loop_read){
			while(filters[j]->stream_elements > 1){
				sleep(1);
			}
		}
		
		if(logging)
			ndd_fill_comm("Done\n", NORMAL_MESSAGE, j);
		
		if(print)
			printf("F#%d => Done\n", j);
		
		filters[j]->stream = NULL;
		ndd_clear_old_rec(&first[j], 999999999999);
	}

	comm_stop = 0;

	for(int i = 1; i <= filters_count; i++){
		if(i == filters_count && !logging)
			break;
		if(pthread_join(th[i], NULL)){
			if(logging)
				ndd_fill_comm("Error joining threads\n", ERROR_MESSAGE, 0);
				fprintf(stderr, "Error joining threads\n");
        	}
	}

	lnf_rec_free(rec);
	if(file_count == 1)
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

void ndd_fill_text_ip_mask(char *target, char *ip, int mask_v4, int mask_v6){
	strcat(target, " net ");
	char tmp[STRING_MAX];
	if(strstr(ip, ".")){
		snprintf(tmp, (strlen(ip)-1), "%s", &ip[2]);
		switch(mask_v4){
			case 24 : {strcat(tmp, " 255.255.255.0");break;}
			case 16 : {strcat(tmp, " 255.255.0.0");break;}
		}
	}else{
		strcat(target, ip);
		sprintf(tmp, "/%d", mask_v6);
	}
	strcat(target, tmp);
}


int ndd_find_attack_pattern(uint64_t file_times[], int file_count, int filter_id, uint64_t threshold, ndd_rec_t *top, char type){
	lnf_rec_t *rec;
	ndd_filter_t *f = filters[filter_id];
	lnf_mem_t *mem_original_dataset;

	int records = 0;
	int temp = 0;
	uint64_t threshold2 = threshold;
	int thstep = f->thstep;
	int top_x = f->max_top_x;
	int max_top_x = 1;
	int active_filters_made = 0;
	int lnf_unit = type == 'B' ? LNF_FLD_DOCTETS : LNF_FLD_DPKTS;

	lnf_rec_init(&rec);
	lnf_mem_init(&mem_original_dataset);

	char msg[STRING_MAX*2];

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

	
	if(logging){
		sprintf(msg, "!!! Entering attack pattern finding |%c|threshold - %lu  !!!\n", type, threshold);
		ndd_fill_comm(msg, ERROR_MESSAGE, filter_id);
	}
	if(print)
		printf("F#%d => !!! Entering attack pattern finding |%c|threshold - %lu  !!!\n", filter_id, type, threshold);

	//fill lnf memory with rec that are processed but not in dataset files
	while(top){
		lnf_rec_fset(rec, LNF_FLD_BREC1, &top->brec);
		lnf_rec_fset(rec, LNF_FLD_TCP_FLAGS, &top->tcp_flags);
		lnf_mem_write(mem_original_dataset, rec);
		top = top->prev;
		temp++;
	}
	
	//read whole dataset
	for(int i = 0; i < file_count; i++){
		lnf_file_t *file;

		char path[STRING_MAX];
		ndd_assemble_filepath(path, f->db_table, file_times[i], i);

		if(lnf_open(&file, path, LNF_READ, NULL) != LNF_OK){
			if(logging){
				sprintf(msg, "Failed to open dataset file %s\n", path);
				ndd_fill_comm(msg, ERROR_MESSAGE, filter_id);
			}
			fprintf(stderr, "F#%d => Failed to open dataset file %s\n", filter_id, path);
			return -1;
		}

		while(lnf_read(file, rec) != LNF_EOF){
			lnf_mem_write(mem_original_dataset, rec);
			records++;
		}

		lnf_close(file);	
	}
	if(logging){
		sprintf(msg, "!!! Found %d (%d in tmp) records in %d files !!!\n", records, temp, file_count);
		ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
	}
	if(print)
		printf("F#%d => !!! Found %d (%d in tmp) records in %d files !!!\n", filter_id, records, temp, file_count);

	// --- 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 ---
	while(1){
		//get active filters
		pthread_mutex_lock(&active_filters_lock);
		lnf_filter_t *act_filters[active_filters_count];
		int act_filters_count = ndd_get_active_filters(act_filters);
		pthread_mutex_unlock(&active_filters_lock);
		
		int aggr_filters_count = 0;
		int filter_candidate[items_count];
		memset(filter_candidate, 0, sizeof(int)*items_count);
		char filter_candidate_text[items_count][STRING_MAX*max_top_x];
		lnf_filter_t *aggr_filters[items_count];
		int ip_mask_v4 = 32;
		int ip_mask_v6 = 128;
		// --- 2 + 3 + 4 + 5 + 6 + 7 + 8 ---
		for(int i = 0; i < items_count; i++){
			if(f->eval_items[i] == 0)
				break;

			//filter and aggregace dataset
			lnf_mem_t *mem_altered_dataset;
			lnf_mem_init(&mem_altered_dataset);

			//--- 4 + 5 + 8 ---
			//set aggregation key based on eval_items information
			if(strstr(items_text[f->eval_items[i]], "ip"))
				lnf_mem_fadd(mem_altered_dataset, items[f->eval_items[i]], LNF_AGGR_KEY, ip_mask_v4, ip_mask_v6);
			else
				lnf_mem_fadd(mem_altered_dataset, items[f->eval_items[i]], LNF_AGGR_KEY, 0, 0);

			//set additional aggregation information
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_FIRST, LNF_AGGR_MIN, 0, 0);
			lnf_mem_fadd(mem_altered_dataset, LNF_FLD_LAST, LNF_AGGR_MAX, 0, 0);
			if(type == 'B'){
				lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DOCTETS, LNF_AGGR_SUM | LNF_SORT_DESC, 0, 0);
				lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DPKTS, LNF_AGGR_SUM, 0, 0);
			}else{
				lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DOCTETS, LNF_AGGR_SUM, 0, 0);
				lnf_mem_fadd(mem_altered_dataset, LNF_FLD_DPKTS, LNF_AGGR_SUM | LNF_SORT_DESC, 0, 0);
			}
			lnf_mem_cursor_t *csr;
			lnf_mem_first_c(mem_original_dataset, &csr);
			
			int passed = 1;
			int rejected = 0;
			uint64_t active_reject = 0;
			uint64_t active_reject_unit = 0;
			uint64_t dataset_baseline = 0;
			uint64_t unit = 0;

			//Always filter the fastest way possible
			if(act_filters_count <= aggr_filters_count){
				while(csr != NULL){
					lnf_mem_read_c(mem_original_dataset, csr, rec);
					lnf_mem_next_c(mem_original_dataset, &csr);
					passed = 1;

					//records REJECTED based on global active_filters
					for(int j = 0; j < act_filters_count; j++){
						if(lnf_filter_match(act_filters[j], rec)){		
							passed = 0;
							lnf_rec_fget(rec, lnf_unit, &unit);
							active_reject_unit += unit;
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
					lnf_rec_fget(rec, lnf_unit, &unit);
					dataset_baseline += unit;
				}
			}else{        
				while(csr != NULL){
					lnf_mem_read_c(mem_original_dataset, csr, rec);
					lnf_mem_next_c(mem_original_dataset, &csr);
					passed = 1;
					rejected = 0;

					//--- 3 ---
					//records SELECTED based on aggr_filter
					for(int j = 0; j < aggr_filters_count; j++){
						if(!lnf_filter_match(aggr_filters[j], rec)){
							passed = 0;
							break;
						}
					}

					if(!passed)
						continue;

					//records REJECTED based on global active_filters
					for(int j = 0; j < act_filters_count; j++){
						if(lnf_filter_match(act_filters[j], rec)){
							rejected = 1;
							lnf_rec_fget(rec, lnf_unit, &unit);
							active_reject_unit += unit;
							active_reject++;
							break;
						}
					}

					if(rejected)
						continue;

					if(passed){
						lnf_mem_write(mem_altered_dataset, rec);
					}
					lnf_rec_fget(rec, lnf_unit, &unit);
					dataset_baseline += unit;
				}

			}

			dataset_baseline = dataset_baseline / f->dataset_window;
			//--- 2 ---
			if(dataset_baseline <= threshold){
				if(logging){
					sprintf(msg, "!!! Ending pattern finding: current < threshold | %lu < %lu (Filtered %lu)!!!\n", dataset_baseline, threshold, active_reject);
					ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
				}
				if(print)
					printf("F#%d => !!! Ending pattern finding: current < threshold | %lu < %lu (Filtered %lu)!!!\n", filter_id, dataset_baseline, threshold, active_reject);
				//EXIT + free everything
				lnf_rec_free(rec);
				lnf_mem_free(mem_original_dataset);
				lnf_mem_free(mem_altered_dataset);
				return active_filters_made;
			}
				
			
			lnf_brec1_t brec;
			uint8_t tcp_flags = 0;
			lnf_mem_first_c(mem_altered_dataset, &csr);
			if(logging){
				char ags[STRING_MAX];
				strcpy(ags, items_text[f->eval_items[i]]);
				if(ip_mask_v4 != 32 && strstr(items_text[f->eval_items[i]], "ip")){
					char masks[STRING_MAX/2];
					sprintf(masks, " (ip masks: v4/%d - v6/%d)", ip_mask_v4, ip_mask_v6);
					strcat(ags, masks);
				}
				sprintf(msg, "Dataset filtered with %d aggr_filters | %d active_filters -> filtered %lu records (%lu%c) | aggregated based on %s | threshold2 %lu\n",
					aggr_filters_count, active_filters_count, active_reject, active_reject_unit, type, ags, threshold2);
				ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
			}
			if(print){
				char ags[STRING_MAX];
				strcpy(ags, items_text[f->eval_items[i]]);
				if(ip_mask_v4 != 32 && strstr(items_text[f->eval_items[i]], "ip")){
					char masks[STRING_MAX/2];
					sprintf(masks, " (ip masks: v4/%d - v6/%d)", ip_mask_v4, ip_mask_v6);
					strcat(ags, masks);
				}
				printf("F#%d => Dataset filtered with %d aggr_filters | %d active_filters -> filtered %lu records (%lu%c) | aggregated based on %s | threshold2 %lu\n",
					filter_id, aggr_filters_count, active_filters_count, active_reject, active_reject_unit, type, ags, threshold2);
			}
			uint64_t first;
			uint64_t last;
			uint64_t top_current = 0;

			records = 0;
			//how many top records are selected
			int index = 0;
			dataset_baseline = 0;
			while(csr != NULL){
				lnf_mem_read_c(mem_altered_dataset, csr, rec);
				if(records < top_x){
					//get number of bytes from top record and transform it into current[bps]
					lnf_rec_fget(rec, LNF_FLD_FIRST, &first);
					lnf_rec_fget(rec, LNF_FLD_LAST, &last);
					lnf_rec_fget(rec, lnf_unit, &top_current);
					uint64_t duration = (last - first) / 1000;
					duration = duration > 0 ? duration : 1;
					top_current = top_current / duration;
					
					char sbuf[INET6_ADDRSTRLEN];
					char dbuf[INET6_ADDRSTRLEN];

					lnf_rec_fget(rec, LNF_FLD_BREC1, &brec);
					lnf_rec_fget(rec, LNF_FLD_TCP_FLAGS, &tcp_flags);
					inet_ntop(AF_INET6, &brec.srcaddr, sbuf, INET6_ADDRSTRLEN);
					inet_ntop(AF_INET6, &brec.dstaddr, dbuf, INET6_ADDRSTRLEN);

					if(logging){
						snprintf(msg, STRING_MAX, "(%d) src %s - %d | dst %s - %d | %lluB - %llupkts | Prot %d - Tcp-flags %d | Current - %lu%cps\n",
							(records+1), sbuf, brec.srcport, dbuf, brec.dstport, (LLUI)brec.bytes, (LLUI)brec.pkts, brec.prot, tcp_flags, top_current, type);
						ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
					}
					if(print){
							printf("F#%d => (%d) src %s - %d | dst %s - %d | %lluB - %llupkts | Prot %d - Tcp-flags %d | Current - %lu%cps\n",
								filter_id, (records+1), sbuf, brec.srcport, dbuf, brec.dstport, (LLUI)brec.bytes, (LLUI)brec.pkts, brec.prot, tcp_flags, top_current, type);
					}

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
								if(ip_mask_v4 == 32){
									strcpy(filter_text, "src ip ");
									strcat(filter_text, buf);
								}else{
									strcpy(filter_text, "src");
									ndd_fill_text_ip_mask(filter_text, buf, ip_mask_v4, ip_mask_v6);	
								}
								break;		       
							}
							case LNF_FLD_DSTADDR : {
								index = 2;
								char buf[INET6_ADDRSTRLEN];
								inet_ntop(AF_INET6, &brec.dstaddr, buf, INET6_ADDRSTRLEN);
								if(ip_mask_v4 == 32){
									strcpy(filter_text, "dst ip ");
									strcat(filter_text, buf);
								}else{
									strcpy(filter_text, "dst");
									ndd_fill_text_ip_mask(filter_text, buf, ip_mask_v4, ip_mask_v6);
								}
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
					}else{
						break;
					}
				}else{
					break;
				}
				records++;
				lnf_mem_next_c(mem_altered_dataset, &csr);
			}
			//When top1 is not enough agregated based on srcip => try to agregate with ip mask lowered
			if(records == 0 && strstr(items_text[f->eval_items[i]], "ip") && ip_mask_v4 != 16){
				ip_mask_v4 = ip_mask_v4 == 32 ? 24 : 16;
				ip_mask_v6 = ip_mask_v6 == 128 ? 64 : 48;
				i--;
				if(logging){
					sprintf(msg, "Failed to fined adequate top1 based on ip aggregation => lowering ip masks : v4/%d - v6/%d\n", ip_mask_v4, ip_mask_v6);
					ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
				}
				if(print){
					printf("F#%d => Failed to fined adequate top1 based on ip aggregation => lowering ip masks : v4/%d - v6/%d\n", filter_id, ip_mask_v4, ip_mask_v6);
				}
				lnf_mem_free(mem_altered_dataset);
				continue;
			}

			ip_mask_v4 = 32;
			ip_mask_v6 = 128;

			if(logging){
				sprintf(msg, "Reducted to %d useful records\n", records);
				ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
			}
			if(print)
				printf("F#%d => Reducted to %d useful records\n", filter_id, records);

			if(index){
				if(logging){
					sprintf(msg, "Added filter_candidate %d - %s\n", index, filter_candidate_text[index]);
					ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
				}
				if(print)
					printf("F#%d => Added filter_candidate %d - %s\n", filter_id, index, filter_candidate_text[index]);
				if(filter_candidate[index] > 1){
					char filter_text[STRING_MAX*max_top_x];
					strcpy(filter_text, "(");
					strcat(filter_text, filter_candidate_text[index]);
					strcat(filter_text, ")");
					strcpy(filter_candidate_text[index], filter_text);
				}

				int con;
				lnf_filter_t *flt;
				if((con = lnf_filter_init_v1(&flt, filter_candidate_text[index])) != LNF_OK){
					if(logging){
						sprintf(msg, "Failed to initialise libnf filter (%d): \"%s\"\n", con, filter_candidate_text[index]);
						ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
					}
					fprintf(stderr, "F#%d => Failed to initialise libnf filter (%d): \"%s\"\n", filter_id, con, filter_candidate_text[index]);
				}else{
					aggr_filters[aggr_filters_count] = flt;
					aggr_filters_count++;
				}
			}else{
				int item_skip = 0;
				for(int j = 0; j < items_count; j++){
					if(f->required_items[j] == 0)
						break;
					if(f->eval_items[i] == f->required_items[j]){
						item_skip = 1;
						break;
					}
				}
				//skip all other items if required-item top1 not good enough
				if(item_skip){
					lnf_mem_free(mem_altered_dataset);
					if(logging){
						sprintf(msg, "Skipping => %s top1 not good enough\n", items_text[f->eval_items[i]]);
						ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
					}
					if(print)
						printf("F#%d => Skipping => %s top1 not good enough\n", filter_id, items_text[f->eval_items[i]]);
					break;
				}
			}

			lnf_mem_free(mem_altered_dataset);
		}
		//end of eval-items loop
		/*
		* Tu by měl být nalpněný filter_candidate -> zkontrolovat vůči required items a udělat filter
		* po udělání filtru se zavolá celá funkce znova
		* pokud se filtr neudělá pak se poníží threshold a udělá se znova celý while procházení eval-items 
		* */

		for(int i = 0; i < aggr_filters_count; i++){
			lnf_filter_free(aggr_filters[i]);
		}

		char found_pattern[STRING_MAX*top_x];
		int first = 1;
		int required_items_counted = 0;
		int matching_filter_candidates_counted = 0;
		int active_sources = 0;
		//--- 9 ---
		for(int i = 0; i < items_count; i++){
			if(f->eval_items[i] == 0)
				break;
			if(filter_candidate[f->eval_items[i]]){
				if(first){
					first = 0;
					strcpy(found_pattern, f->filter_string);
					strcat(found_pattern, " AND ");
					strcat(found_pattern, filter_candidate_text[f->eval_items[i]]);
				}else{
					strcat(found_pattern, " AND ");
					strcat(found_pattern, filter_candidate_text[f->eval_items[i]]);
				}
				active_sources += filter_candidate[f->eval_items[i]];
			}
			if(filter_candidate[f->required_items[i]])
				matching_filter_candidates_counted++;
			if(f->required_items[i] > 0)
				required_items_counted++;
		}

		if(logging){
			sprintf(msg, "Filter_candidate contains %d items from Required_items (%d needed)\n", matching_filter_candidates_counted, required_items_counted);
			ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
		}

		if(print)
			printf("F#%d => Filter_candidate contains %d items from Required_items (%d needed)\n", filter_id, matching_filter_candidates_counted, required_items_counted);
		

		if(required_items_counted == matching_filter_candidates_counted){
			//--- 10 ---
			if(logging){
				snprintf(msg, STRING_MAX, "Pattern : %s\n", found_pattern);
				ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
			}
			if(print)
				printf("F#%d => Pattern : %s\n", filter_id, found_pattern);

			int con;
			lnf_filter_t *flt;
			if((con = lnf_filter_init_v1(&flt, found_pattern)) != LNF_OK){
				if(logging){
					snprintf(msg, STRING_MAX, "Failed to initialise libnf filter (%d): \"%s\"\n", con, found_pattern);
					ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
				}
				fprintf(stderr, "F#%d => Failed to initialise libnf filter (%d): \"%s\"\n", filter_id, con, found_pattern);
				break;
			}else{
				if(logging){
					snprintf(msg, STRING_MAX, "Filter \"%s\" (%p) initialized and added to active_filters(#%d)\n", found_pattern, flt, active_filters_count);
					ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
				}
				if(print)
					printf("F#%d => Filter \"%s\" (%p) initialized and added to active_filters(#%d)\n", filter_id, found_pattern, flt, active_filters_count);
			}
			ndd_add_active_filter(flt, found_pattern, f->active_filter_duration, f->db_table);
			active_filters_made++;
			threshold2 = threshold;
			thstep = f->thstep;
			if(logging){
				sprintf(msg, "Threshold2 reseting to %lu\n", threshold2);
				ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
			}
			if(print)
				printf("F#%d => Threshold2 reseting to %lu\n", filter_id, threshold2);
		}else{
			if(logging)
				ndd_fill_comm("Insufficient filter_candidate contents to make active_filter\n", NORMAL_MESSAGE, filter_id);
			if(print)
				printf("F#%d => Insufficient filter_candidate contents to make active_filter\n", filter_id);
			
			//--- 11 ---
			thstep--;
			//--- 12 ---
			if(thstep == 0){
				if(logging)
					ndd_fill_comm("!!! Ending pattern finding: thstep -> 0 !!!\n", NORMAL_MESSAGE, filter_id);
				if(print)
					printf("F#%d => !!! Ending pattern finding: thstep -> 0 !!!\n", filter_id);
				break;
			}
			threshold2 = (threshold / f->thsteps) * thstep;
			if(logging){
				sprintf(msg, "Threshold2 getting lowered to %lu\n", threshold2);
				ndd_fill_comm(msg, NORMAL_MESSAGE, filter_id);
			}
			if(print)
				printf("F#%d => Threshold2 getting lowered to %lu\n", filter_id, threshold2);
		}
	}

	lnf_rec_free(rec);
	lnf_mem_free(mem_original_dataset);
	return active_filters_made;
}
