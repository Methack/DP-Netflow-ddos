
#include <libnf.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>

typedef struct Ndd_rec_t Ndd_rec_t;
struct Ndd_rec_t{
	uint64_t time;
	uint64_t bytes;
	uint64_t packets;
	int processed;
	Ndd_rec_t *next;
};

#define FILTER "src port 53"
#define BASELINE_WINDOW 300 //[s]
#define MAX_NEWEST_CUTOFF 20
#define COEFFICIENT 300


void ndd_init_rec(Ndd_rec_t **rec, Ndd_rec_t *last){
	Ndd_rec_t *r = malloc(sizeof(Ndd_rec_t));
        if(r){
                r->time = 0;
                r->bytes = 0;
                r->packets = 0;
                r->processed = 0;
                r->next = NULL;
                if(last)
                        last->next = r;

                *rec = r;
        }
}

void ndd_free_rec(Ndd_rec_t *rec, Ndd_rec_t **first){
	if(rec){
                if(rec->next){
                        *first = rec->next;
			printf("Free -%p- first -%p-\n", rec, (*first));
		}else{
			*first = NULL;
		}
                free(rec);
        }
}

void ndd_free_rec_processed(Ndd_rec_t *rec, Ndd_rec_t **first){	
        while(rec){
                if(rec->processed){
			ndd_free_rec(rec, first);
			rec = *first;
                }else{
                        *first = rec;
                        break;
                }
        }
        if(rec == NULL){
                *first = NULL;
        }
}

void ndd_print_rec(Ndd_rec_t *first, int id, int process){
        Ndd_rec_t *r = first;
        int i = 1;
        printf("----------------------------------------\n");
        printf("Recs for filter #%d : \n", id);
        while(r){
                printf("(%d) -%p- -next: %p- time: %lu -  bytes: %lu - packets: %lu - Processed #%d#\n", i, r, r->next, r->time, r->bytes, r->packets, r->processed);
                i++;
		if(process)
			r->processed = 1;
                r = r->next;
        }
}


int ndd_process_filter_stream(int id, Ndd_rec_t **rec){
	//Get filter information
	Ndd_filter_t *f = filters[id];
	
	Ndd_rec_t *r = (*rec);

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
	uint64_t time = 0;
	uint64_t bytes = 0;
	uint64_t packets = 0;

	//information
	int values_count = 0;
	for(int i = 0; i < col_count; i++){
		if(f->db_columns[i])
			values_count++;
	}
	uint64_t values_to_insert[values_count];

	while(1){
		if(r->processed && r->next == NULL){
			break;
			//sleep(0.01);
			//continue;
		}else if(!r->processed){
			;
		}else if(r->next){
				r = r->next;
		}
		
		//get information from rec
		time = r->time;
                bytes = r->bytes;
                packets = r->packets;
                r->processed = 1;
                printf("Rec -%p- is being processed \n", r);
		printf("Bytes %lu - time %lu - packast %lu\n", bytes, time, packets);


		//total number of bytes send in current baseline window
                bts_sum += bytes;
		
		//total number of packets send in current baseline window
                pks_sum += packets;

                //remove ms
                time = time / 1000;

                //first time
                if(newest == 0)
                        newest = time;

                //calculate index to bps
                cid = (time - newest) + nid;
                //correct index to within bounds
                cid = cid < 0 ? cid + f->baseline_window : cid >= f->baseline_window ? cid - f->baseline_window : cid;

                //new newest time
                if(newest < time){
                        int dif = time - newest;
                        if(dif < f->max_newest_cutoff){
				//move in time
                                sec_prev_insert += dif;
                                newest = time;

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
                        }else{
				//current flow is much newer => add it to current second
                                cid = nid;
                        }
                }


                if(cid < 0){
                        //flow is older than baseline window => add to oldest second
                        if(cid == (f->baseline_window-1)){
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
                                successful_insert++;
                        }else{
                                failed_insert++;
                        }
                        sec_prev_insert = 0;
                }
	}

	return 0;
}


int process_file(){
        lnf_file_t *filep;
        lnf_rec_t *rec;

        int loopread = 0;

        if(lnf_open(&filep, nfcapd_current, LNF_READ | loopread ? LNF_READ_LOOP : 0, NULL) != LNF_OK){
                fprintf(stderr, "Failed to open file %s\n", nfcapd_current);
                exit(1);
        }

        lnf_rec_init(&rec);

        int ret;

        uint64_t time;
        uint64_t bytes;
        uint64_t packets;

        Ndd_rec_t *first[filters_count];
        Ndd_rec_t *last[filters_count];
        for(int i = 0; i < filters_count; i++){
                first[i] = NULL;
                last[i] = NULL;
        }

	//fork

        int count = 0;

	while(1){
                ret = lnf_read(filep, rec);

                if(ret == LNF_EOF){
                        break;
                }

                for(int i = 1; i < filters_count; i++){
                        if(lnf_filter_match(filters[i]->filter, rec)){
                                lnf_rec_fget(rec, LNF_FLD_DOCTETS, &bytes);
                                if(bytes == 0)
                                        break;

                                lnf_rec_fget(rec, LNF_FLD_FIRST, &time);
                                //lnf_rec_fget(rec, LNF_FLD_LAST, &time);
                                lnf_rec_fget(rec, LNF_FLD_DPKTS, &packets);

                                //Remove processed
                                ndd_free_rec_processed(first[i], &first[i]);
                                if(first[i] == NULL)
                                        last[i] = NULL;

                                //Create new and append
                                ndd_init_rec(&last[i], last[i]);
                                if(first[i] == NULL)
                                        first[i] = last[i];

                                last[i]->time = time;
                                last[i]->bytes = bytes;
                                last[i]->packets = packets;
                        }
                }
                if(count > 20){
                        break;
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