#include "config.h"

int ndd_config_parse_fint(int value, int field, ndd_filter_t *f, ndd_filter_t *d, int line_number){
	int *target_value;
	switch (field){
		case NDD_BASELINE_WINDOW : {
			if(f == NULL){
				target_value = &d->baseline_window;
			}else{
				target_value = &f->baseline_window;
				if(d->baseline_window < 0)
					d->baseline_window = value;
			}
			break;
		}
		case NDD_MAX_NEWEST_CUTOFF : {
			if(f == NULL){
				target_value = &d->max_newest_cutoff;	     
			}else{
				target_value = &f->max_newest_cutoff;
				if(d->max_newest_cutoff < 0)
					d->max_newest_cutoff = value;
			}
			break;
		}
		case NDD_COEFFICIENT : {
			if(f == NULL){
				target_value = &d->coefficient;
			}else{
				target_value = &f->coefficient;
				if(d->coefficient < 0)
					d->coefficient = value;
			}
			break;		
		}
		case NDD_DB_INSERT_INTERVAL : {
			if(f == NULL){
				target_value = &d->db_insert_interval;
			}else{
				target_value = &f->db_insert_interval;
				if(d->db_insert_interval < 0)
					d->db_insert_interval = value;
			}
			break;		
		}
		case NDD_MAX_BASELINE_INCREASE : {
			if(f == NULL){
				target_value = &d->max_baseline_increase;
			}else{
				target_value = &f->max_baseline_increase;
				if(d->max_baseline_increase < 0)
					d->max_baseline_increase = value;
			}	
		     	break;	
		}
		case NDD_THSTEP : {
			if(f == NULL){
				target_value = &d->thstep;
			}else{
				target_value = &f->thstep;
				if(d->thstep < 0)
					d->thstep = value;
			}
			break;
		}
		case NDD_THSTEPS : {
			if(f == NULL){
				target_value = &d->thsteps;
			}else{
				target_value = &f->thsteps;
				if(d->thsteps < 0)
					d->thsteps = value;
			}
			break;		
		}
		case NDD_DATASET_WINDOW : {
			if(f == NULL){
				target_value = &d->dataset_window;
			}else{
				target_value = &f->dataset_window;
				if(d->dataset_window < 0)
					d->dataset_window = value;
			}
			break;
		}
		case NDD_DATASET_CHUNKS : {
			if(f == NULL){
				target_value = &d->dataset_chunks;
			}else{
				target_value = &f->dataset_chunks;
				if(d->dataset_chunks < 0)
					d->dataset_chunks = value;
			}
			break;
		}
		case NDD_ACTIVE_FILTER_DURATION : {
			if(f == NULL){
				target_value = &d->active_filter_duration;
			}else{
				target_value = &f->active_filter_duration;
				if(d->active_filter_duration < 0)
					d->active_filter_duration = value;
			}
			break;
		}
		case NDD_MAX_TOP_X : {
			if(f == NULL){
				target_value = &d->max_top_x;
			}else{
				target_value = &f->max_top_x;
				if(d->max_top_x < 0)
					d->max_top_x = value;
			}
			break;
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

int ndd_active_array_items(int *arr, int length){
	int active_items = 0;
	for(int i = 0; i < length; i++){
		if(arr[i] > 0)
			active_items++;
	}
	return active_items;
}

void ndd_fill_items(char* tmp, int *target){
	int positions[items_count];
	memset(&positions[0], '0', items_count*sizeof(int));
	int found = 0;
        //find positions
	for(int i = 1; i < items_count; i++){
		char *pos = strstr(tmp, items_text[i]);
		if(pos){
			found++;
			positions[i] = (int)(pos - tmp) + 1;
		}
	}
	//fill target
	for(int i = 0; i < found; i++){
		int min_position = 0;
		int min_position_index = 0;
		for(int j = 1; j < items_count; j++){
			if(positions[j] == 0)
				continue;
			if(min_position == 0 || min_position > positions[j]){
				min_position = positions[j];
				min_position_index = j;
			}
		}
		target[i] = min_position_index;
		positions[min_position_index] = 0;
	}
}

int ndd_config_parse(){
	FILE *file = fopen("./ndd.conf", "r");
	int line_number = 0;

	//Temporary array with pointers to filters
	ndd_filter_t *ptr_filters[50];

	char line[STRING_MAX];
	char tmp[STRING_MAX];
	int itmp;
	int skip = 0;
	int files_expected = file_count;

	if(file_count > 1){
		nfcapd_files = malloc(file_count * sizeof(char *));
		if(!nfcapd_files){
			fprintf(stderr, "Failed to allocate memory\n");
			exit(1);
		}
		for(int i = 0; i < file_count; i++){
			nfcapd_files[i] = NULL;
		}

	}
	ndd_filter_t *f1 = NULL;

	ndd_filter_t *defaults;
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
		if(sscanf(line, " nfcapd_file = \"%[^\"]", tmp)){
			if(files_expected == 0){
				fprintf(stderr, "Found more definitions of nfcapd_file than expected on line %d\n", line_number);
				continue;
			}
			if(access(tmp, F_OK) != 0){
				fprintf(stderr, "File doesn't exist: %s\n", tmp);
				continue;
			}
			if(file_count > 1){
				nfcapd_files[file_count - files_expected] = strdup(tmp);
			}else{
				nfcapd_current = strdup(tmp);
			}
			files_expected--;
			continue;
		}
		//Connection string
		if(sscanf(line, " connection_string = \"%[^\"]",tmp)){
			if(connection_string){
				fprintf(stderr, "Reccuring definiton of connection_string found on line %d\n", line_number);
				continue;
			}
			connection_string = strdup(tmp);
			//check db connection and create necessary tables
			if(!ndd_db_check_and_prepare()){
				exit(1);
			}
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
		//Eval_items
		if(sscanf(line, " eval_items = \"%[^\"]", tmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			if(f1)
				ndd_fill_items(tmp, f1->eval_items);
			else
				ndd_fill_items(tmp, defaults->eval_items);
			continue;
		}
		//Required_items
		if(sscanf(line, " required_items = \"%[^\"]", tmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			if(f1)
				ndd_fill_items(tmp, f1->required_items);
			else
				ndd_fill_items(tmp, defaults->required_items);
			continue;
		}
		//Baseline_window
		if(sscanf(line, " baseline_window = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_BASELINE_WINDOW, f1, defaults, line_number);
			continue;
		}
		//Max_newest_cutoff
		if(sscanf(line, " max_newest_cutoff = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_MAX_NEWEST_CUTOFF, f1, defaults, line_number);
			continue;
		}
		//Coefficient
		if(sscanf(line, " coefficient = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_COEFFICIENT, f1, defaults, line_number);
			continue;
		}
		//Db_insert_interval
		if(sscanf(line, " db_insert_interval = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_DB_INSERT_INTERVAL, f1, defaults, line_number);
			continue;
		}
		//Max_baseline_increase
		if(sscanf(line, " max_baseline_increase = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_MAX_BASELINE_INCREASE, f1, defaults, line_number);
			continue;
		}
		//Dataset_window
		if(sscanf(line, " dataset_window = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_DATASET_WINDOW, f1, defaults, line_number);
			continue;
		}
		//Dataset_chunks
		if(sscanf(line, " dataset_chunks = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_DATASET_CHUNKS, f1, defaults, line_number);
			continue;
		}
		//Thsteps
		if(sscanf(line, " thsteps = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_THSTEPS, f1, defaults, line_number);
			continue;
		}
		//Thstep
		if(sscanf(line, " thstep = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_THSTEP, f1, defaults, line_number);
			continue;
		}
		if(sscanf(line, " active_filter_duration = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_ACTIVE_FILTER_DURATION, f1, defaults, line_number);
			continue;
		}
		if(sscanf(line, " max_top_x = %d", &itmp)){
			if(skip) //Skip - This value bellongs to failed filter
				continue;
			ndd_config_parse_fint(itmp, NDD_MAX_TOP_X, f1, defaults, line_number);
			continue;
		}

		fprintf(stderr, "Syntax error parsing config on line %d\n", line_number);
	}

	//Close file stream
	fclose(file);

	//No db connection_string in config, abort
	if(!connection_string){
		fprintf(stderr, "Missing connection_string in config\n");
		exit(1);
	}
	
	//No nfcapd_current path in config, abort
	if(!nfcapd_current && file_count == 1){
		fprintf(stderr, "Missing nfcapd_file in config\n");
		exit(1);
	}

	if(file_count > 1){
		for(int i = 0; i < file_count; i++){
			if(!nfcapd_files[i]){
				fprintf(stderr, "Missing one or more nfcapd_files in config\n");
				exit(1);
			}
		}
	}

	//Failed to create dataset dir, abort
	if(mkdir("./datasets/", 0777) && errno != EEXIST){
		fprintf(stderr, "Failed to create dataset dir - %s\n", strerror(errno));
		exit(1);
	}


	//Current time - used for unique db table names
	char t[11];
	snprintf(t, 11, "%"PRIu64, (uint64_t)time(NULL));

	int fc = 1;
	//Check missing values and insert default ones
	for(int i = 1; i <= filters_count; i++){
		ndd_filter_t *f = ptr_filters[i];
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
				fprintf(stderr, "Missing default value for coefficient - Value \'%d\' will be used\n", DEFAULT_COEFFICIENT);
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
		if(!ndd_active_array_items(f->db_columns, col_count)){
			if(!ndd_active_array_items(defaults->db_columns, col_count)){
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
				fprintf(stderr, "Missing default value for max_baseline_increase - Value \'%d\' will be used\n", DEFAULT_MAX_BASELINE_INCREASE);
				defaults->max_baseline_increase = DEFAULT_MAX_BASELINE_INCREASE;
			}
			f->max_baseline_increase = defaults->max_baseline_increase;
		}
		if(!ndd_active_array_items(f->eval_items, items_count)){
			if(!ndd_active_array_items(defaults->eval_items, items_count)){
				fprintf(stderr, "Missing default value for eval_items - These will be used : dstip srcip\n");
				defaults->eval_items[0] = 2;
				defaults->eval_items[1] = 1;
			}
			for(int i = 0; i < items_count; i++){
				f->eval_items[i] = defaults->eval_items[i];
			}
		}
		if(!ndd_active_array_items(f->required_items, items_count)){
			if(!ndd_active_array_items(defaults->required_items, items_count)){
				fprintf(stderr, "Missing default value for required_items - These will be used : dstip srcip\n");
				defaults->required_items[0] = 2;
				defaults->required_items[1] = 1;
			}
			for(int i = 0; i < items_count; i++){
				f->required_items[i] = defaults->required_items[i];
			}
		}
		if(f->dataset_window < 0){
			if(defaults->dataset_window < 0){
				fprintf(stderr, "Missing default value for dataset_window - Value \'%d\' will be used\n", DEFAULT_DATASET_WINDOW);
				defaults->dataset_window = DEFAULT_DATASET_WINDOW;
			}
			f->dataset_window = defaults->dataset_window;
		}
		if(f->dataset_chunks < 0){
			if(defaults->dataset_chunks < 0){
				fprintf(stderr, "Missing default value for dataset_chunks - Value \'%d\' will be used\n", DEFAULT_DATASET_CHUNKS);
				defaults->dataset_chunks = DEFAULT_DATASET_CHUNKS;
			}
			f->dataset_chunks = defaults->dataset_chunks;
		}
		if(f->thsteps < 0){
			if(defaults->thsteps < 0){
				fprintf(stderr, "Missing default value for thsteps - Value \'%d\' will be used\n", DEFAULT_THSTEPS);
				defaults->thsteps = DEFAULT_THSTEPS;
			}
			f->thsteps = defaults->thsteps;
		}
		if(f->thstep < 0){
			if(defaults->thstep < 0){
				fprintf(stderr, "Missing default value for thstep - Value \'%d\' will be used\n", DEFAULT_THSTEP);
				defaults->thstep = DEFAULT_THSTEP;
			}
			f->thstep = defaults->thstep;
		}
		if(f->active_filter_duration < 0){
			if(defaults->active_filter_duration < 0){
				fprintf(stderr, "Missing default value for active_filter_duration - Value \'%d\' will be used\n", DEFAULT_ACTIVE_FILTER_DURATION);
				defaults->active_filter_duration = DEFAULT_ACTIVE_FILTER_DURATION;
			}
			f->active_filter_duration = defaults->active_filter_duration;
		}
		if(f->max_top_x < 0){
			if(defaults->max_top_x < 0){
				fprintf(stderr, "Missing default value for max_top_x - Value \'%d\' will be used\n", DEFAULT_MAX_TOP_X);
				defaults->max_top_x = DEFAULT_MAX_TOP_X;
			}
			f->max_top_x = defaults->max_top_x;
		}

		//Create table in db
		char tmp[STRING_MAX];
		sprintf(tmp, "ndd%sf%d",t,i);
		if(!ndd_db_create_table(tmp, f->db_columns, f->filter_string)){
			//Failed to create table
			fprintf(stderr, "Failed to create table \'%s\', filter will be skipped\n", tmp);
			ptr_filters[i] = NULL;
			ndd_free_filter(f, 0);
			continue;
		}
		printf("Table created \'%s\'\n", tmp);
		f->db_table = strdup(tmp);

		//Create file for datasets
		char dataset_path[STRING_MAX];
		strcpy(dataset_path, "./datasets/");
		strcat(dataset_path, tmp);
		strcat(dataset_path, "/");
		int ret = mkdir(dataset_path, 0777);
		if(ret == -1){
			fprintf(stderr, "Failed to create dataset dir for \'%s\', filter will be skipped\n", f->db_table);
			ptr_filters[i] = NULL;
			ndd_free_filter(f, 1);
			continue;
		}
		printf("Dataset dir created \'%s\'\n", dataset_path);
		fc++;
	}
	
	filters = malloc(sizeof(ndd_filter_t *) * fc);

	if(!filters){
		fprintf(stderr, "Couldn't allocate memory for filters\n");
		exit(1);
	}

	printf("Found file paths in order: %d\n", file_count);
	if(file_count == 1){
		printf("	%s\n", nfcapd_current);
	}else{
		for(int i = 0; i < file_count; i++){
			printf("	%s\n", nfcapd_files[i]);	
		}
	}
	//Fill global filters container
	int c = 0;
	for(int i = 0; i <= filters_count; i++){
		if(ptr_filters[i]){
			filters[c] = ptr_filters[i];
			ndd_print_filter_info(filters[c], c, stdout, 's');
			c++;
		}
	}
	filters_count = c;
	if(c <= 1){
		fprintf(stderr, "No valid input-filter detected\n");
		exit(1);
	}
	printf("Total number of detected filters - %d\n", filters_count-1);
	
	return 0;
}

