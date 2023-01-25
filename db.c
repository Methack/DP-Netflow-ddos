#include <libnf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <inttypes.h>

//from nfddos
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))


#define INSERT_OK 1
#define INSERT_FAIL 0

int db_insert_baseline(uint64_t timestamp, uint64_t baseline){
	PGresult *res;
	PGconn *db;

	db = PQconnectdb("dbname=pgnetflowddos user=xjires02");
	if(PQstatus(db) == CONNECTION_BAD){
		fprintf(stderr, "Failed to connect to db %s", PQerrorMessage(db));
		return INSERT_FAIL;
	}
	
	const char sql[] = "INSERT INTO baseline(time, value) VALUES (to_timestamp($1), $2)";
	char btimestamp[11];
	snprintf(btimestamp, 11, "%"PRIu64, timestamp);
	uint64_t bbaseline = htonll(baseline);
	const char * const paramValues[] = {btimestamp, (char *)&bbaseline};
	const int paramLengths[] = {11, sizeof(uint64_t)};
	const int paramFormats[] = {0,1};

	res = PQexecParams(db, sql, 2, NULL, paramValues, paramLengths, paramFormats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		fprintf(stderr, "Failed to insert: %s", PQresultErrorMessage(res));
		return INSERT_FAIL;
	}
	PQclear(res);

	PQfinish(db);
	
	return INSERT_OK; 
}
