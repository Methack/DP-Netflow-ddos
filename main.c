#include <libnf.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>

#include "db.c"


#define FILTER "src port 443"
#define BASELINE_WINDOW 300 //[s]
#define MAX_NEWEST_CUTOFF 20
#define COEFFICIENT 300

int process_file(char *file, lnf_filter_t *filter1){
	lnf_file_t *filep;
	lnf_rec_t *rec;
	
	int loopread = 1;

	if(lnf_open(&filep, file, LNF_READ | loopread ? LNF_READ_LOOP : 0, NULL) != LNF_OK){
		return 0;
	}

	lnf_rec_init(&rec);

	int ret;
	int match = 0;

	uint64_t bps[BASELINE_WINDOW];
	memset(bps, 0, BASELINE_WINDOW*sizeof(uint64_t));
	uint64_t bts = 0;
	uint64_t pps[BASELINE_WINDOW];
	memset(pps, 0, BASELINE_WINDOW*sizeof(uint64_t));
	uint64_t pks = 0;

	uint64_t newest = 0;
	int nid = 0;
	uint64_t bt_baseline = 0;
	uint64_t pk_baseline = 0;

	uint64_t bt_diff = 0;
	uint64_t pk_diff = 0;

	int new = 0;
	int nnew = 0;

	int failed = 0;


	uint64_t time;
	uint64_t bytes;
	uint64_t packets;

	int i = 0;
	int dif;
	int index;
	while(1){
		ret = lnf_read(filep, rec);
		
		if(ret == LNF_EOF){
			break;
		}

		match = 1;
		if(filter1 != NULL){
			match = lnf_filter_match(filter1, rec);
		}
		if(match){
			lnf_rec_fget(rec, LNF_FLD_FIRST, &time);
			//lnf_rec_fget(rec, LNF_FLD_LAST, &time);
		    	lnf_rec_fget(rec, LNF_FLD_DOCTETS, &bytes);
			lnf_rec_fget(rec, LNF_FLD_DPKTS, &packets);	
			
			if(bytes == 0)
				continue;

			//total number of bytes send in current baseline window
			bts += bytes;
			
			pks += packets;

			//remove ms
			time = time / 1000;

			//first time
			if(newest == 0)
				newest = time;

			//calculate index to bps
			i = (time - newest) + nid;
			//correct index to within bounds
			i = i < 0 ? i + BASELINE_WINDOW : i >= BASELINE_WINDOW ? i - BASELINE_WINDOW : i;
			
			//new newest time
			if(newest < time){
				dif = time - newest;
				//current flow is much newer
				if(dif < MAX_NEWEST_CUTOFF){
					new += dif;
					newest = time;
					for(int j = 1; j <= dif; j++){
						index = nid + j;
					
						//correct index to within bounds
						index = index >= BASELINE_WINDOW ? index - BASELINE_WINDOW : index;
					
						//clear oldest flows
						bts -= bps[index];
						bps[index] = 0;

						pks -= pps[index];
						pps[index] = 0;
                                		
					}
					nid = i;
				}else{
					i = nid;
				}
			}
			
			//compute new baseline for bytes per second
            		bt_baseline = (bt_baseline + (bts / BASELINE_WINDOW) * COEFFICIENT) / (COEFFICIENT + 1);

            		//compute new baseline for packets per second
            		pk_baseline = (pk_baseline + (pks / BASELINE_WINDOW) * COEFFICIENT) / (COEFFICIENT + 1);


			if(i < 0){
				//Flow is older than baseline window => add to oldest second
				if(nid == (BASELINE_WINDOW-1)){
					bps[0] += bytes;
					pps[0] += packets;
				}else{
					bps[nid+1] += bytes;
					pps[nid+1] += packets;
				}
			}else{
				//add bytes to specific second
				bps[i] += bytes;
				pps[i] += packets;
					
				//pomocné hodnoty - nedůležité
				bt_diff = (bt_diff < (bps[i] - bt_baseline)) ? (bps[i] - bt_baseline) : bt_diff;
			    	pk_diff = (pk_diff < (pps[i] - pk_baseline)) ? (pps[i] - pk_baseline) : pk_diff;	
			}


			if(new >= 60){
				if(db_insert_baseline(newest, bt_baseline, pk_baseline, bt_diff, pk_diff)){
					nnew++;
				}else{
					failed++;
				}
				new = 0;
				bt_diff = 0;
				pk_diff = 0;
			}
        	}
	}
	
	lnf_close(filep);

	return 0;
}

//WIP - z nfddos
int daemonize(){
	pid_t pid, sid;
	pid = fork();
	if(pid < 0){return 0;}
	if(pid > 0){exit(0);}
	sid = setsid();
	if(sid < 0){return 0;}
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	return 1;
}

int main(int argc, char **argv){

	char *file;

	if(argc == 2){
		file = argv[1];
		if(!daemonize()){
			fprintf(stderr, "Failed to daemonize");
			return 1;	
		}
	}else if(argc == 3){
		file = argv[1];
	}else{
		printf("arg\n");
		return 0;
	}

	int con;

	lnf_filter_t *filter1;
	if((con = lnf_filter_init_v1(&filter1, FILTER)) != LNF_OK){
		return 1;
	}
	int rows;

	rows = process_file(file, filter1);
	(void) rows;

	return 0;
}
