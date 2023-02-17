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


int ndd_db_insert_baseline(uint64_t timestamp, uint64_t bt_baseline, uint64_t pk_baseline, uint64_t bps, uint64_t pps){
	PGresult *res;
	PGconn *db;

	if(!(db = ndd_db_connect()))
		return COMMAND_FAIL;

	const char sql[] = "INSERT INTO test(time, bytes, packets, bps, pps) VALUES (to_timestamp($1), $2, $3, $4, $5)";
	char btimestamp[11];
	snprintf(btimestamp, 11, "%"PRIu64, timestamp);
	uint64_t bbaseline = htonll(bt_baseline);
	uint64_t pbaseline = htonll(pk_baseline);
	uint64_t bdiff = htonll(bps);
	uint64_t pdiff = htonll(pps);
	
	const char * const paramValues[] = {btimestamp, (char *)&bbaseline, (char *)&pbaseline, (char *)&bdiff, (char *)&pdiff};
	const int paramLengths[] = {11, sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
	const int paramFormats[] = {0, 1, 1, 1, 1};
	res = PQexecParams(db, sql, 5, NULL, paramValues, paramLengths, paramFormats, 0);
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


	printf("SQL to exec -> %s\n", sql);

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
	//CREATE TABLE table (v1 t1, v2 t2, ...);
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




