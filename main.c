
#include <libnf.h>
#include <string.h>
#include <time.h>

#include "db.c"


#define FILTER "src port 443"
#define BASELINE_WINDOW 300 //[s]
#define MAX_NEWEST_CUTOFF 20

int process_file(char *file, lnf_filter_t *filter1){
	lnf_file_t *filep;
	lnf_rec_t *rec;
	
	int loopread = 1;

	if(lnf_open(&filep, file, LNF_READ | loopread ? LNF_READ_LOOP : 0, NULL) != LNF_OK){
		fprintf(stderr, "Failed to open file %s\n", file);
		return 0;
	}

	lnf_rec_init(&rec);

	int ret;
	int count = 0;
	int match = 0;
	int count_match1 = 0;

	uint64_t bps[BASELINE_WINDOW];
	memset(bps, 0, BASELINE_WINDOW*sizeof(uint64_t));
	uint64_t bts = 0;
	uint64_t newest = 0;
	int nid = 0;
	uint64_t baseline;

	int new = 0;
	int nnew = 0;

	int failed = 0;

	while(1){
		ret = lnf_read(filep, rec);
		
		if(ret == LNF_EOF){
			printf("EOF\n");
			break;
		}

		count++;


		match = 1;
		if(filter1 != NULL){
			match = lnf_filter_match(filter1, rec);
		}
		if(match){
			uint64_t timea;
			uint64_t bytes;
			
			lnf_rec_fget(rec, LNF_FLD_FIRST, &timea);
		    	lnf_rec_fget(rec, LNF_FLD_DOCTETS, &bytes);
			
			if(bytes == 0)
				continue;

			//total number of bytes send in current baseline window
			bts += bytes;
			
			//remove ms
			timea = timea / 1000;

			//first time
			if(newest == 0)
				newest = timea;

			//calculate index to bps
			int i = (timea - newest) + nid;
			//correct indew to within bounds
			i = i < 0 ? i + BASELINE_WINDOW : i >= BASELINE_WINDOW ? i - BASELINE_WINDOW : i;

			//new newest time
			if(newest < timea){
				int dif = timea - newest;
				//current flow is much newer
				if(dif < MAX_NEWEST_CUTOFF){
					
					new += dif;
					newest = timea;
					for(int j = 1; j <= dif; j++){
						int index = nid + j;
					
						//correct index to within bounds
						index = index >= BASELINE_WINDOW ? index - BASELINE_WINDOW : index;
					
						//clear oldest flows
						bts -= bps[index];
						bps[index] = 0;
                                		
					}
					nid = i;

				}else{
					printf("MAX_NEWEST_CUTOFF - newer by %ds\n", dif);
					i = nid;
				}
			}
			
			if(i < 0){
				//Flow is older than baseline window => add to oldest second
				if(nid == (BASELINE_WINDOW-1))
					bps[0] += bytes;
				else
					bps[nid+1] += bytes;
			}else{
				//add bytes to specific second
				bps[i] += bytes;

			}

			baseline = bts / BASELINE_WINDOW;
			if(new >= 60){
				if(db_insert_baseline(newest, baseline)){
					time_t t = time(NULL);
					nnew++;
					printf("%d(-%d): Baseline inserted - %lu - %s",nnew, failed, baseline, asctime(gmtime(&t)));
				}else{
					failed++;
				}
				new = 0;
			}
                        count_match1++;
                }
	}
	
	printf("Baseline - %lu\n", baseline);

	lnf_close(filep);

	printf("Matched 1 results : %d\n", count_match1);
	return count;
}

int main(int argc, char **argv){
	char *file;
	char *filter_prototype = NULL;

	if(argc == 2){
		file = argv[1];
	}else{
		printf("arg\n");
		return 0;
	}

	printf("%s => Filter1: %s", file, FILTER);
	
	int con;
	lnf_filter_t *filter1;
	if((con = lnf_filter_init_v1(&filter1, FILTER)) != LNF_OK){
		fprintf(stderr, "Failed to initialise filter: %s\n", FILTER);
		return 1;
	}
	int rows;

	rows = process_file(file, filter1, filter2);


	printf("Total records read : %d\n", rows);

	return 0;
}


