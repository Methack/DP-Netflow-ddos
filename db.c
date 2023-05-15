#include "db.h"

PGconn *ndd_db_connect(){
	if(!connection_string)
		return NULL;
	PGconn *db;
	db = PQconnectdb(connection_string);
	if(PQstatus(db) == CONNECTION_BAD){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to connect to db | %s", PQerrorMessage(db));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to connect to db | %s", PQerrorMessage(db));
		return NULL;
	}
	return db;
}


int ndd_db_insert(uint64_t time, uint64_t values[], char *table, int columns[]){
	PGresult *res;
	PGconn *db;

	if(!(db = ndd_db_connect()))
		return COMMAND_FAIL;
	
	int values_count = 0;

	//create sql command for specific filter
	//possible sql => "INSERT INTO test(time, bytes, packets, bps, pps) VALUES (to_timestamp($1), $2, $3, $4, $5)";
	char sql[STRING_MAX];
	strcpy(sql, "INSERT INTO ");
	strcat(sql, table);
	strcat(sql, " (time");
	//add columns
	for(int i = 0; i < col_count; i++){
		if(columns[i]){
			strcat(sql, ", ");
			strcat(sql, col[i]);
		}
	}
	strcat(sql, ") VALUES (to_timestamp($1)");
	//add $
	for(int i = 0; i < col_count; i++){
		if(columns[i]){
			char tmp[20];
			sprintf(tmp, ", $%d", (values_count+2));
			strcat(sql, tmp);
			values_count++;
		}
	}
	strcat(sql, ")");
		
	//transform timestamp into pg friendly format
	char timestamp[11];
	snprintf(timestamp, 11, "%"PRIu64, time);
	
	//inicialize arrays
	const char *param_values[values_count+1];
	int param_lengths[values_count+1];
	int param_formats[values_count+1];

	//insert timestamp values into arrays
	param_values[0] = timestamp;
	param_lengths[0] = 11;
	param_formats[0] = 0;

	//insert specific values for every column
	uint64_t htonll_values[values_count];
	for(int i = 0; i < values_count; i++){
		htonll_values[i] = htonll(values[i]);
		param_values[i+1] = (char *)&htonll_values[i];
		param_lengths[i+1] = sizeof(uint64_t);
		param_formats[i+1] = 1;
	}
	
	res = PQexecParams(db, sql, (values_count+1), NULL, param_values, param_lengths, param_formats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to insert baseline: %s", PQresultErrorMessage(res));
			char num[11];
			strcpy(num, table+13);
			ndd_fill_comm(msg, ERROR_MESSAGE, atoi(num)); 
		}
		
		fprintf(stderr, "Failed to insert baseline: %s", PQresultErrorMessage(res));
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;
	}

	PQclear(res);
	PQfinish(db);
	
	return COMMAND_OK; 
}

int ndd_db_exec_sql(char *sql){
	PGresult *res;
	PGconn *db;

	if(!(db = ndd_db_connect()))
		return COMMAND_FAIL;

	res = PQexec(db, sql);

	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to execute \"%s\" : %s", sql, PQresultErrorMessage(res));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to execute \"%s\" : %s", sql, PQresultErrorMessage(res));
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;
	}

	PQclear(res);
	PQfinish(db);

	return COMMAND_OK;
}

int ndd_db_drop_table(char *table){
	
	char sql[STRING_MAX];
	strcpy(sql, "DROP TABLE ");
	strcat(sql, table);
	
	if(!ndd_db_exec_sql(sql)){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed drop table %s\n", table);
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed drop table %s\n", table);
		return COMMAND_FAIL;
	}
	return COMMAND_OK;
}

int ndd_db_insert_filters(char *table, char *filter_string){
	PGresult *res;
	PGconn *db;

	if(!(db = ndd_db_connect())){
		return COMMAND_FAIL;
	}

	char *sql = "INSERT INTO filters (id, filter) VALUES ($1, $2)";

	const char * const param_values[] = {table, filter_string};

	res = PQexecParams(db, sql, 2, NULL, param_values, NULL, NULL, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to insert filter info: %s", PQresultErrorMessage(res));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to insert filter info: %s", PQresultErrorMessage(res));
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;
	}

	PQclear(res);
	PQfinish(db);

	return COMMAND_OK;
}

int ndd_db_insert_detection(char *table, uint64_t time, uint64_t current, uint64_t prev, char type){
	PGconn *db;
	PGresult *res;

	if(!(db = ndd_db_connect())){
		return COMMAND_FAIL;
	}

	char *sql = "INSERT INTO detected (id, time, baseline, prev_baseline, type) VALUES ($1, to_timestamp($2), $3, $4, $5)";

	//transform timestamp into pg friendly format
	char timestamp[11];
	snprintf(timestamp, 11, "%"PRIu64, time);

	
	uint64_t c = htonll(current);
	uint64_t p = htonll(prev);

	char *unit;
	if(type == 'B')
		unit = "byte";
	else
		unit = "packet";

	const char * const param_values[] = {table, timestamp, (char *)&c, (char *)&p, unit};
	const int param_formats[] = {1,0,1,1,1};
	const int param_lengths[] = {strlen(table), 11, sizeof(uint64_t), sizeof(uint64_t), strlen(unit)};

	

	res = PQexecParams(db, sql, 5, NULL, param_values, param_lengths, param_formats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to insert detection: %s", PQresultErrorMessage(res));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to insert detection: %s", PQresultErrorMessage(res));
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;
	}
	PQclear(res);
	PQfinish(db);

	return COMMAND_OK;
}

int ndd_db_insert_active_filter(char *table, char *filter_string, uint64_t start, uint64_t end){
	PGconn *db;
	PGresult *res;

	if(!(db = ndd_db_connect())){
		return COMMAND_FAIL;
	}

	char *sql = "INSERT INTO active_filters (id, filter, start, stop) VALUES ($1, $2, to_timestamp($3), to_timestamp($4))";

	char start_timestamp[11];
	snprintf(start_timestamp, 11, "%"PRIu64, start);
	char end_timestamp[11];
	snprintf(end_timestamp, 11, "%"PRIu64, end);

	const char * const param_values[] = {table, filter_string, start_timestamp, end_timestamp};
	const int param_formats[] = {1,1,0,0};
	const int param_lengths[] = {strlen(table), strlen(filter_string), 11, 11};

	res = PQexecParams(db, sql, 4, NULL, param_values, param_lengths, param_formats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to insert active_filter: %s", PQresultErrorMessage(res));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to insert active_filter: %s", PQresultErrorMessage(res));
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;
	}
	PQclear(res);
	PQfinish(db);

	return COMMAND_OK;
}

int ndd_db_update_active_filter(ndd_activef_t *a){
	PGconn *db;
	PGresult *res;

	if(!(db = ndd_db_connect())){
		return COMMAND_FAIL;
	}

	char *sql = "UPDATE active_filters SET filtered_bytes = $1, filtered_packets = $2 WHERE filter LIKE $3 AND stop = to_timestamp($4)";	
		
	char timestamp[11];
	snprintf(timestamp, 11, "%"PRIu64, a->tstop);
	
	uint64_t b = htonll(a->filtered_bytes);
	uint64_t p = htonll(a->filtered_packets);
		
	const char * const param_values[] = {(char *)&b, (char *)&p, a->filter_string, timestamp};
	const int param_formats[] = {1,1,1,0};
	const int param_lengths[] = {sizeof(uint64_t), sizeof(uint64_t), strlen(a->filter_string), 11};
	
	res = PQexecParams(db, sql, 4, NULL, param_values, param_lengths, param_formats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to insert active_filter: %s", PQresultErrorMessage(res));
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to update active_filter: %s", PQresultErrorMessage(res));
		
		PQclear(res);
		PQfinish(db);
		return COMMAND_FAIL;	
	}
	
	PQclear(res);
	PQfinish(db);
	return COMMAND_OK;
}

int ndd_db_create_table(char *table, int v[], char *filter_string){
	//Create sql string
	char sql[STRING_MAX];
	strcpy(sql, "CREATE TABLE ");
	strcat(sql, table);
	strcat(sql, " (time timestamp");

	for(int i = 0; i < col_count; i++){
		if(v[i]){
			strcat(sql, ", ");
			strcat(sql, col[i]);
			strcat(sql, " bigint");
		}
	}
	strcat(sql, ")");

	//Try to create table for filter
	if(!ndd_db_exec_sql(sql)){
		if(logging){
			char msg[STRING_MAX];
			snprintf(msg, STRING_MAX, "Failed to create table %s\n", table);
			ndd_fill_comm(msg, ERROR_MESSAGE, 0);
		}
		fprintf(stderr, "Failed to create table %s\n", table);
		return COMMAND_FAIL;
	}

	//Successfully created table for filter, now try to insert its information into 'filters' table
	if(ndd_db_insert_filters(table, filter_string))
		return COMMAND_OK;

	//Failed to insert info into db => delete table created before
	if(ndd_db_drop_table(table)){
		if(logging)
		ndd_fill_comm("Failed to insert into filters\n", ERROR_MESSAGE, 0);
		fprintf(stderr, "Failed to insert into filters\n");
		return COMMAND_FAIL;
	}
	
	//Failed to delete table created before
	if(logging)
		ndd_fill_comm("Multiple failures when trying to establish new filter in db\n", ERROR_MESSAGE, 0);
	fprintf(stderr, "Multiple failures when trying to establish new filter in db\n");
	return COMMAND_FAIL;
}

int ndd_db_check_and_prepare(){
	//table 'filters' contains:
	//	'id' - table name of specific filter
	//	'filter' - filter string specified in config
	//	'active' - if filter is active (ndd instance is storing information into this filters table)
	char *sql_f = "CREATE TABLE IF NOT EXISTS filters (id varchar(20), filter text, active boolean DEFAULT true)";

	//table 'detected' contains:
	//	'id' - table name of specific filter
	//	'time' - timestamp when detection occourred
	//	'basline' - current baseline in time of detection
	//	'prev_baseline' - previous baseline that is being compared to current one
	char *sql_d = "CREATE TABLE IF NOT EXISTS detected (id varchar(20), time timestamp, baseline bigint, prev_baseline bigint)";
	
	//table 'active_filters' contains:
	//	'id' - table name of specificfilter
	//	'filter' - filter string of found pattern
	//	'start' - time of filter start
	//	'stop' - time of filter end
	char *sql_a = "CREATE TABLE IF NOT EXISTS active_filters (id varchar(20), filter text, start timestamp, stop timestamp)";
	
	//try to create table for filters
	if(!ndd_db_exec_sql(sql_f))
		return COMMAND_FAIL;

	//try to create table for detected
	if(!ndd_db_exec_sql(sql_d))
		return COMMAND_FAIL;

	//try to create table for active_filters
	if(!ndd_db_exec_sql(sql_a))
		return COMMAND_FAIL;

	//successfully created both tables
	return COMMAND_OK;
}


