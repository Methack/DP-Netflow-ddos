#include <libnf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <inttypes.h>

//from nfddos
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))


#define COMMAND_OK 1
#define COMMAND_FAIL 0

PGconn *ndd_db_connect(){
        if(!connection_string)
        	return NULL;
	PGconn *db;
	db = PQconnectdb(connection_string);
	if(PQstatus(db) == CONNECTION_BAD){
                fprintf(stderr, "Failed to connect to db %s", PQerrorMessage(db));
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
		fprintf(stderr, "Failed to insert: %s", PQresultErrorMessage(res));
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
                fprintf(stderr, "Failed to insert: %s", PQresultErrorMessage(res));
                PQclear(res);
                PQfinish(db);
                return COMMAND_FAIL;
        }

        PQclear(res);
        PQfinish(db);

        return COMMAND_OK;
}

int ndd_db_insert_detection(char *table, uint64_t time, uint64_t current, uint64_t prev){
	PGconn *db;
	PGresult *res;

	if(!(db = ndd_db_connect())){
                return COMMAND_FAIL;
        }

	char *sql = "INSERT INTO detected (id, time, baseline, prev_baseline) VALUES ($1, to_timestamp($2), $3, $4)";

	//transform timestamp into pg friendly format
	char timestamp[11];
	snprintf(timestamp, 11, "%"PRIu64, time);

	
	uint64_t c = htonll(current);
	uint64_t p = htonll(prev);

	const char * const param_values[] = {table, timestamp, (char *)&c, (char *)&p};
	const int param_formats[] = {1,0,1,1};
	const int param_lengths[] = {strlen(table), 11, sizeof(uint64_t), sizeof(uint64_t)};

	

	res = PQexecParams(db, sql, 4, NULL, param_values, param_lengths, param_formats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
                fprintf(stderr, "Failed to insert: %s", PQresultErrorMessage(res));
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
		fprintf(stderr, "Failed to create table %s\n", table);
		return COMMAND_FAIL;
	}

	//Successfully created table for filter, now try to insert its information into 'filters' table
	if(ndd_db_insert_filters(table, filter_string))
		return COMMAND_OK;

	//Failed to insert info into db => delete table created before
	if(ndd_db_drop_table(table)){
		fprintf(stderr, "Failed to insert into filters\n");
		return COMMAND_FAIL;
	}
	
	//Failed to delete table created before
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
	//	'baseline' - current baseline in time of detection
	//	'prev_baseline' - previous baseline that is being compared to current one
	char *sql_d = "CREATE TABLE IF NOT EXISTS detected (id varchar(20), time timestamp, baseline bigint, prev_baseline bigint)";
	
	//try to create table for filters
	if(!ndd_db_exec_sql(sql_f)){
		return COMMAND_FAIL;
	}

	//try to create table for detected
	if(!ndd_db_exec_sql(sql_d)){
		return COMMAND_FAIL;
	}

	//successfully created both tables
	return COMMAND_OK;
}


