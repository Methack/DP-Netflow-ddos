#ifndef __DB_H_
#define __DB_H_

#include <libnf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <inttypes.h>

#include "nddstruct.h"

//from nfddos
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))


#define COMMAND_OK 1
#define COMMAND_FAIL 0

//global variables
extern char *connection_string;
extern int logging;

//db.c functions
PGconn *ndd_db_connect();
int ndd_db_insert(uint64_t time, uint64_t values[], char *table, int columns[]);
int ndd_db_exec_sql(char *sql);
int ndd_db_drop_table(char *table);
int ndd_db_insert_filters(char *table, char *filter_string);
int ndd_db_insert_detection(char *table, uint64_t time, uint64_t current, uint64_t prev, char type);
int ndd_db_insert_active_filter(char *table, char *filter_string, uint64_t start, uint64_t end);
int ndd_db_update_active_filter(ndd_activef_t *a);
int ndd_db_create_table(char *table, int v[], char *filter_string);
int ndd_db_check_and_prepare();

#endif

