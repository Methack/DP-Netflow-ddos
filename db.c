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
		
	char timestamp[11];
	snprintf(timestamp, 11, "%"PRIu64, time);
	
	const char *param_values[values_count+1];
	int param_lengths[values_count+1];
	int param_formats[values_count+1];

	param_values[0] = timestamp;
	param_lengths[0] = 11;
	param_formats[0] = 0;

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

int ndd_db_create_table(char *table, int v[]){
	//Possible v - byte_baseline, bps, packet_baseline, pps
	
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

	if(!ndd_db_exec_sql(sql)){
		fprintf(stderr, "Failed to create table %s\n", table);
		return COMMAND_FAIL;
	}
	return COMMAND_OK;
}




