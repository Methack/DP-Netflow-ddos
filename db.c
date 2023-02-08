#include <libnf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <inttypes.h>

//from nfddos
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))


#define INSERT_OK 1
#define INSERT_FAIL 0

int db_insert_baseline(uint64_t timestamp, uint64_t bt_baseline, uint64_t pk_baseline, uint64_t bt_diff, uint64_t pk_diff){
	PGresult *res;
	PGconn *db;

	db = PQconnectdb("dbname=pgnetflowddos user=xjires02");
	if(PQstatus(db) == CONNECTION_BAD){
		return INSERT_FAIL;
	}
	
	const char sql[] = "INSERT INTO baseline(time, bytes, packets, bdiff, pdiff) VALUES (to_timestamp($1), $2, $3, $4, $5)";
	char btimestamp[11];
	snprintf(btimestamp, 11, "%"PRIu64, timestamp);
	uint64_t bbaseline = htonll(bt_baseline);
	uint64_t pbaseline = htonll(pk_baseline);
	uint64_t bdiff = htonll(bt_diff);
	uint64_t pdiff = htonll(pk_diff);
	
	const char * const paramValues[] = {btimestamp, (char *)&bbaseline, (char *)&pbaseline, (char *)&bdiff, (char *)&pdiff};
	const int paramLengths[] = {11, sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t)};
	const int paramFormats[] = {0, 1, 1, 1, 1};
	res = PQexecParams(db, sql, 5, NULL, paramValues, paramLengths, paramFormats, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		return INSERT_FAIL;
	}
	PQclear(res);

	
	PQfinish(db);
	
	return INSERT_OK; 
}
