#ifndef __CONFIG_H_
#define __CONFIG_H_

#include <errno.h>
#include <sys/stat.h>

#include "db.h"
#include "nddstruct.h"

//PROGRAM DEFAULT VALUES
#define DEFAULT_BASELINE_WINDOW         300
#define DEFAULT_DATASET_WINDOW          30
#define DEFAULT_DATASET_CHUNKS          6
#define DEFAULT_THSTEP                  4
#define DEFAULT_THSTEPS                 4
#define DEFAULT_ACTIVE_FILTER_DURATION	300
#define DEFAULT_MAX_NEWEST_CUTOFF       20
#define DEFAULT_COEFFICIENT             300
#define DEFAULT_DB_INSERT_INTERVAL      60
#define DEFAULT_MAX_BASELINE_INCREASE   3
#define DEFAULT_MAX_TOP_X		1

#define NDD_BASELINE_WINDOW             0x01
#define NDD_DATASET_WINDOW              0x02
#define NDD_DATASET_CHUNKS              0x03
#define NDD_THSTEP                      0x04
#define NDD_THSTEPS                     0x05
#define NDD_MAX_NEWEST_CUTOFF           0x06
#define NDD_COEFFICIENT                 0x07
#define NDD_DB_INSERT_INTERVAL          0x08
#define NDD_MAX_BASELINE_INCREASE       0x09
#define NDD_ACTIVE_FILTER_DURATION	0x0A
#define NDD_MAX_TOP_X			0x0B

//global_variables
extern const int col_count;
extern const char col[4][16];
extern const int items_count;
extern const char items_text[7][10];
extern char *connection_string;
extern char *nfcapd_current;
extern int filters_count;
extern ndd_filter_t **filters;
extern int file_count;
extern char **nfcapd_files;


//config.c functions
int ndd_config_parse_fint(int value, int field, ndd_filter_t *f, ndd_filter_t *d, int line_number);
int ndd_active_array_items(int *arr, int length);
void ndd_fill_items(char* tmp, int *target);
int ndd_config_parse();

#endif

