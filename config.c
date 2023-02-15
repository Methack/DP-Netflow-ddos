#include <stdio.h>
#include <string.h>
#include <libnf.h>

#define STRING_MAX 1024
#define DEFAULT_BASELINE_WINDOW 300
#define DEFAULT_MAX_NEWEST_CUTOFF 20
#define DEFAULT_COEFFICIENT 300
#define DEFAULT_DB_INSERT_INTERVAL 60



typedef struct {
	lnf_filter_t *filter;
	char *filter_string;
	int baseline_window;
	int max_newest_cutoff;
	int coefficient;
	int db_insert_interval;
}Ndd_filter_t;

void ndd_init_filter(Ndd_filter_t **f, char *filters){
	Ndd_filter_t *p = malloc(sizeof(Ndd_filter_t));
	if(p){	
		p->filter = NULL;
		p->filter_string = strdup(filters);
		p->baseline_window = -1;
		p->max_newest_cutoff = -1;
		p->coefficient = -1;
		p->db_insert_interval = -1;
		*f = p;
	}
}

void ndd_free_filter(Ndd_filter_t *f){
	lnf_filter_free(f->filter);
	free(f->filter_string);
	free(f);
}

void ndd_print_filter_info(Ndd_filter_t *f, int i){
	printf("----------------------------------------\n");
	printf("Filter (%d) : %s\n", i, f->filter_string);
	printf("Values : Baseline_window - %d\n", f->baseline_window);
	printf("	 Max_newest_cutoff - %d\n", f->max_newest_cutoff);
	printf("	 Coefficient - %d\n", f->coefficient);
	printf("	 Db_insert_interval - %d\n", f->db_insert_interval);
}

int ndd_config_parse_fint(int value, char what, Ndd_filter_t *f, Ndd_filter_t *d, int line_number){
	int *target_value;
	switch (what){
		case 'b' : {
			if(f == NULL)
				target_value = &d->baseline_window;
			else
				target_value = &f->baseline_window;
			break;
		}
		case 'm' : {
			if(f == NULL)
				target_value = &d->max_newest_cutoff;	     
			else
				target_value = &f->max_newest_cutoff;
			break;
		}
		case 'c' : {
			if(f == NULL)
				target_value = &d->coefficient;
			else
				target_value = &f->coefficient;
			break;		
		}
		case 'd' : {
			if(f == NULL)
				target_value = &d->db_insert_interval;
			else
				target_value = &f->db_insert_interval;
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

int ndd_config_parse(){
	FILE *file = fopen("./ndd.conf", "r");
	int line_number = 0;

	//Number of different filters detected
	int filters = 1;

	//Temporary array with pointers to filters
	Ndd_filter_t *ptr_filters[20];

	char line[STRING_MAX];
	char tmp[STRING_MAX];
	int itmp;
	int skip;

	Ndd_filter_t *f1 = NULL;

	Ndd_filter_t *defaults;
	ndd_init_filter(&defaults, "default");
	ptr_filters[0] = defaults;

	while(fgets(line, STRING_MAX, file)){
		line_number++;

		//EOF
		if(sscanf(line, " %s", tmp) == EOF)
			continue;
		//Comments
		if(sscanf(line, " %[#]", tmp))
			continue;
		//New Filter
		if(sscanf(line, " filter = \"%[^\"]", tmp)){
			int con;
                	lnf_filter_t *f;
			if((con = lnf_filter_init_v1(&f, tmp)) != LNF_OK){
                        	fprintf(stderr, "Failed to initialise libnf filter (%d): \"%s\" on line %d\n", con, tmp, line_number);
                        	skip = 1;
                        	continue;
                	}
		
                	ndd_init_filter(&f1, tmp);

                	f1->filter = f;
			ptr_filters[filters] = f1;
			filters++;

 			skip = 0;
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

		fprintf(stderr, "Syntax error parsing config on line %d\n", line_number);
	}

	//Check missing values and insert default ones
	for(int i = 0; i < filters; i++){
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

		ndd_print_filter_info(f, i);
	}

	return filters;
}
