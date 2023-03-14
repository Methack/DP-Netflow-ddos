#include <time.h>

#define DEFAULT_BASELINE_WINDOW 300
#define DEFAULT_MAX_NEWEST_CUTOFF 20
#define DEFAULT_COEFFICIENT 300
#define DEFAULT_DB_INSERT_INTERVAL 60
#define DEFAULT_MAX_BASELINE_INCREASE 3

void ndd_init_filter(Ndd_filter_t **f, char *fs, char *t){
	Ndd_filter_t *p = malloc(sizeof(Ndd_filter_t));
	if(p){	
		p->filter = NULL;
		p->filter_string = strdup(fs);
		p->stream = NULL;
		pthread_mutex_init(&p->stream_lock, NULL);
		p->stream_elements_ready = 0;
		if(t)
			p->db_table = strdup(t);
		p->baseline_window = -1;
		p->max_newest_cutoff = -1;
		p->coefficient = -1;
		p->db_insert_interval = -1;
		p->max_baseline_increase = -1;
		memset(p->db_columns, 0, col_count*sizeof(int));
		*f = p;
	}
}

void ndd_free_filter(Ndd_filter_t *f, int delete_table){
	if(f){
		lnf_filter_free(f->filter);
		free(f->filter_string);
		//Check if data stored in database, by this filter, is to be removed
		if(delete_table)
			if(ndd_db_drop_table(f->db_table))
                        	printf("Table dropped - %s\n", f->db_table);

		if(f->db_table)
			free(f->db_table);
		free(f);
	}
}

void ndd_print_filter_info(Ndd_filter_t *f, int i){
	if(f){
		printf("----------------------------------------\n");
		printf("Filter (%d) : %s\n", i, f->filter_string);
		printf("DB table : %s\n", f->db_table);
		printf("DB columns : ");
		for(int i = 0; i < col_count; i++){
			if(f->db_columns[i] == 1)
				printf("%s ", col[i]);
		}
		printf("\nValues : Baseline_window - %d\n", f->baseline_window);
		printf("	 Max_newest_cutoff - %d\n", f->max_newest_cutoff);
		printf("	 Coefficient - %d\n", f->coefficient);
		printf("	 db_insert_interval - %d\n", f->db_insert_interval);
		printf("	 Max_baseline_increase - %d\n", f->max_baseline_increase);
	}
}

int ndd_config_parse_fint(int value, char what, Ndd_filter_t *f, Ndd_filter_t *d, int line_number){
	int *target_value;
	switch (what){
		case 'b' : {
			if(f == NULL){
				target_value = &d->baseline_window;
			}else{
				target_value = &f->baseline_window;
				if(d->baseline_window < 0)
					d->baseline_window = value;
			}
			break;
		}
		case 'm' : {
			if(f == NULL){
				target_value = &d->max_newest_cutoff;	     
			}else{
				target_value = &f->max_newest_cutoff;
				if(d->max_newest_cutoff < 0)
					d->max_newest_cutoff = value;
			}
			break;
		}
		case 'c' : {
			if(f == NULL){
				target_value = &d->coefficient;
			}else{
				target_value = &f->coefficient;
				if(d->coefficient < 0)
					d->coefficient = value;
			}
			break;		
		}
		case 'd' : {
			if(f == NULL){
				target_value = &d->db_insert_interval;
			}else{
				target_value = &f->db_insert_interval;
				if(d->db_insert_interval < 0)
					d->db_insert_interval = value;
			}
			break;		
		}
		case 'i' : {
			if(f == NULL){
				target_value = &d->max_baseline_increase;
			}else{
				target_value = &f->max_baseline_increase;
				if(d->max_baseline_increase < 0)
					d->max_baseline_increase = value;
			}	   
		}
	}

	if(*target_value > 0){
		if(f == NULL)
			fprintf(stderr, "Multiple default values detected on line %d\n", line_number);
		else
			fprintf(stderr, "Recurring values in one filter detected on line %d\n", line_number);
		return 1;
	}
	
	*target_value = value;

	return 0;
}

int ndd_active_columns(int *arr){
	int active_columns = 0;
	for(int i = 0; i < col_count; i++){
		if(arr[i] == 1)
			active_columns++;
	}
	return active_columns;
}

int ndd_config_parse(){
	FILE *file = fopen("./ndd.conf", "r");
	int line_number = 0;

	//Temporary array with pointers to filters
	Ndd_filter_t *ptr_filters[50];

	char line[STRING_MAX];
	char tmp[STRING_MAX];
	int itmp;
	int skip = 0;

	Ndd_filter_t *f1 = NULL;

	Ndd_filter_t *defaults;
	ndd_init_filter(&defaults, "default values", "NONE");
	ptr_filters[0] = defaults;

	while(fgets(line, STRING_MAX, file)){
		line_number++;

		//EOF
		if(sscanf(line, " %s", tmp) == EOF)
			continue;
		//Comments
		if(sscanf(line, " %[#]", tmp))
			continue;
		//Nfcapd_current - source file
		if(sscanf(line, " nfcapd_current = \"%[^\"]", tmp)){
			if(nfcapd_current){
				fprintf(stderr, "Reccuring definition of nfcapd_current found on line %d\n", line_number);
				continue;
			}
			nfcapd_current = strdup(tmp);
			continue;
		}
		//Connection string
		if(sscanf(line, " connection_string = \"%[^\"]",tmp)){
			if(connection_string){
				fprintf(stderr, "Reccuring definiton of connection_string found on line %d\n", line_number);
				continue;
			}
			connection_string = strdup(tmp);
			PGconn *db;
			if(!(db = ndd_db_connect())){
                		fprintf(stderr, "Failed to connect to db with connection_string \"%s\"\n", connection_string);
				exit(1);
			}
			PQfinish(db);
			continue;		
		}
		//New Filter
		if(sscanf(line, " filter = \"%[^\"]", tmp)){
			int con;
                	lnf_filter_t *f;
			if((con = lnf_filter_init_v1(&f, tmp)) != LNF_OK){
                        	fprintf(stderr, "Failed to initialise libnf filter (%d): \"%s\" on line %d\n", con, tmp, line_number);
                        	skip = 1;
                        	continue;
                	}
			
			filters_count++;

                	ndd_init_filter(&f1, tmp, NULL);

                	f1->filter = f;
			ptr_filters[filters_count] = f1;
			
			skip = 0;
	                continue;
		}
		//Columns
		if(sscanf(line, " columns = \"%[^\"]", tmp)){
			if(skip) //Skip - This value bellongs to failed filter
                                continue;
			for(int i = 0; i < col_count; i++){
				if(strstr(tmp, col[i])){
					if(f1){
						f1->db_columns[i] = 1;
					}else{
						defaults->db_columns[i] = 1;
					}
				}

			}
			continue;
		}
		//Baseline_window
		if(sscanf(line, " baseline_window = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
	                ndd_config_parse_fint(itmp, 'b', f1, defaults, line_number);
			continue;
		}
		//Max_newest_cutoff
		if(sscanf(line, " max_newest_cutoff = %d", &itmp)){
                	if(skip) //Skip - This value bellongs to failed filter
                                continue;
                        ndd_config_parse_fint(itmp, 'm', f1, defaults, line_number);
                        continue;
		}
		//Coefficient
		if(sscanf(line, " coefficient = %d", &itmp)){
                	if(skip) //Skip - This value bellongs to failed filter
                                continue;
                        ndd_config_parse_fint(itmp, 'c', f1, defaults, line_number);
                        continue;
		}
		//Db_insert_interval
		if(sscanf(line, " db_insert_interval = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
                                continue;
                        ndd_config_parse_fint(itmp, 'd', f1, defaults, line_number);
                        continue;
                }
		//Max_baseline_increase
		if(sscanf(line, " max_baseline_increase = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
                                continue;
			ndd_config_parse_fint(itmp, 'i', f1, defaults, line_number);
                        continue;
		}

		fprintf(stderr, "Syntax error parsing config on line %d\n", line_number);
	}

	//Close file stream
	fclose(file);

	if(!connection_string){
		fprintf(stderr, "Missing connection_string in config\n");
		exit(1);
	}

	if(!nfcapd_current){
		fprintf(stderr, "Missing nfcapd_current in config\n");
		exit(1);
	}

	//Current time - used for unique db table names
        char t[11];
        snprintf(t, 11, "%"PRIu64, (uint64_t)time(NULL));

	int fc = 1;
	//Check missing values and insert default ones
	for(int i = 1; i <= filters_count; i++){
		Ndd_filter_t *f = ptr_filters[i];
		if(f->baseline_window < 0){
			if(defaults->baseline_window < 0){
				fprintf(stderr, "Missing default value for baseline_window - Value \'%d\' will be used\n", DEFAULT_BASELINE_WINDOW);
				defaults->baseline_window = DEFAULT_BASELINE_WINDOW;
			}
			f->baseline_window = defaults->baseline_window;
		}
		if(f->max_newest_cutoff < 0){
			if(defaults->max_newest_cutoff < 0){
				fprintf(stderr, "Missing default value for max_newest_cutoff - Value \'%d\' will be used\n", DEFAULT_MAX_NEWEST_CUTOFF);
				defaults->max_newest_cutoff = DEFAULT_MAX_NEWEST_CUTOFF;
			}
			f->max_newest_cutoff = defaults->max_newest_cutoff;
		}
		if(f->coefficient < 0){
			if(defaults->coefficient < 0){
				fprintf(stderr, "Missing default value for coefficient - Values \'%d\' will be used\n", DEFAULT_COEFFICIENT);
				defaults->coefficient = DEFAULT_COEFFICIENT;
			}
			f->coefficient = defaults->coefficient;
		}
		if(f->db_insert_interval < 0){
			if(defaults->db_insert_interval < 0){
				fprintf(stderr, "Missing default value for db_insert_interval - Value \'%d\' will be used\n", DEFAULT_DB_INSERT_INTERVAL);
				defaults->db_insert_interval = DEFAULT_DB_INSERT_INTERVAL;
			}
			f->db_insert_interval = defaults->db_insert_interval;
		}
		if(!ndd_active_columns(f->db_columns)){
			if(!ndd_active_columns(defaults->db_columns)){
				fprintf(stderr, "Missing default active DB columns list - These will be used : ");
				for(int i = 0; i < col_count; i++){
					defaults->db_columns[i] = 1;
					fprintf(stderr, "%s ", col[i]);
				}
				fprintf(stderr, "\n");
			}
			for(int i = 0; i < col_count; i++){
				f->db_columns[i] = defaults->db_columns[i];
			}
		}
		if(f->max_baseline_increase < 0){
			if(defaults->max_baseline_increase < 0){
				fprintf(stderr, "Missing default value for max_baseline_increase - Values \'%d\' will be used\n", DEFAULT_MAX_BASELINE_INCREASE);
				defaults->max_baseline_increase = DEFAULT_MAX_BASELINE_INCREASE;
			}
			f->max_baseline_increase = defaults->max_baseline_increase;
		}
		
		char tmp[STRING_MAX];
                sprintf(tmp, "ndd%sf%d",t,i);
		if(!ndd_db_create_table(tmp, f->db_columns, f->filter_string)){
			//Failed to create table
			ptr_filters[i] = NULL;
			ndd_free_filter(f, 0);
			continue;
                }
		printf("Table created %s\n", tmp);
		f->db_table = strdup(tmp);
		fc++;
	}
	
	filters = malloc(sizeof(Ndd_filter_t)*fc);

        if(!filters){
                fprintf(stderr, "Couldn't allocate memory for filters\n");
                exit(1);
        }


	//Fill global filters container
	int c = 0;
	for(int i = 0; i <= filters_count; i++){
		if(ptr_filters[i]){
			filters[c] = ptr_filters[i];
			ndd_print_filter_info(filters[c], c);
			c++;
		}
	}
	filters_count = c;
	
	return 0;
}

