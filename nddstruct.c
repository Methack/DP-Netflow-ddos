
#include "nddstruct.h"

/*
 * ndd_filter_t functions
 */

void ndd_init_filter(ndd_filter_t **f, char *fs, char *t){
        ndd_filter_t *p = malloc(sizeof(ndd_filter_t));
        if(p){
                p->filter = NULL;
                p->filter_string = strdup(fs);
                p->stream = NULL;
                pthread_mutex_init(&p->stream_lock, NULL);
                p->stream_elements = 0;
                if(t)
                        p->db_table = strdup(t);
                p->baseline_window = -1;
                p->dataset_window = -1;
                p->dataset_chunks = -1;
                memset(p->eval_items, 0, items_count*sizeof(int));
                memset(p->required_items, 0, items_count*sizeof(int));
                p->thsteps = -1;
                p->thstep = -1;
                p->max_newest_cutoff = -1;
                p->coefficient = -1;
                p->db_insert_interval = -1;
                p->max_baseline_increase = -1;
                memset(p->db_columns, 0, col_count*sizeof(int));
                *f = p;
        }
}

void ndd_free_filter(ndd_filter_t *f, int delete_table){
        if(f){
                lnf_filter_free(f->filter);
                free(f->filter_string);
                //Check if data stored in database, by this filter, is to be removed
                if(delete_table && f->db_table[1] != 'O'){
                        if(ndd_db_drop_table(f->db_table))
                                printf("Table dropped - %s\n", f->db_table);
                        char sql[STRING_MAX];
                        strcpy(sql, "DELETE FROM filters WHERE id LIKE '");
                        strcat(sql, f->db_table);
                        strcat(sql, "';");
                        if(ndd_db_exec_sql(sql))
                                printf("Removed from filters - %s\n", f->db_table);
                }else if(f->db_table[1] != 'O'){
                        char sql[STRING_MAX];
                        strcpy(sql, "UPDATE filters SET active = false WHERE id LIKE '");
                        strcat(sql, f->db_table);
                        strcat(sql, "';");
                        if(ndd_db_exec_sql(sql))
                                printf("Filter %s set as inactive in filters table\n", f->db_table);
                }

                if(f->db_table)
                        free(f->db_table);
                free(f);
        }
}

void ndd_print_filter_info(ndd_filter_t *f, int i, FILE *stream, char dest){
        if(f){
                fprintf(stream, "----------------------------------------\n");
                fprintf(stream, "Filter (%d) : %s\n", i, f->filter_string);
                if(dest == 'f'){
                        if(f->stream)
                                fprintf(stream, "Activity : ACTIVE\n");
                        else
                                fprintf(stream, "Activity : NOT ACTIVE\n");
                }
                fprintf(stream, "DB table : %s\n", f->db_table);
                fprintf(stream, "DB columns : ");
                for(int i = 0; i < col_count; i++){
                        if(f->db_columns[i] == 1)
                                fprintf(stream, "%s ", col[i]);
                }
                fprintf(stream, "\nValues : Baseline_window - %d\n", f->baseline_window);
                fprintf(stream, "        Max_newest_cutoff - %d\n", f->max_newest_cutoff);
                fprintf(stream, "        Coefficient - %d\n", f->coefficient);
                fprintf(stream, "        Db_insert_interval - %d\n", f->db_insert_interval);
                fprintf(stream, "        Max_baseline_increase - %d\n", f->max_baseline_increase);
                fprintf(stream, "        Dataset_window - %d\n", f->dataset_window);
                fprintf(stream, "        Dataset_chunks - %d\n", f->dataset_chunks);
                fprintf(stream, "        Thsteps - %d | Thstep - %d\n", f->thsteps, f->thstep);
                fprintf(stream, "        Eval_items : ");
                for(int i = 0; i < items_count; i++){
                        if(f->eval_items[i] > 0)
                                fprintf(stream, "%s ", items_text[f->eval_items[i]]);
                }
                fprintf(stream, "\n");
                fprintf(stream, "         Required_items : ");
                for(int i = 0; i < items_count; i++){
                        if(f->required_items[i] > 0)
                                fprintf(stream, "%s ", items_text[f->required_items[i]]);
                }
                fprintf(stream, "\n");
        }
}

/*
 * ndd_rec_t functions
 */

void ndd_init_rec(ndd_rec_t **rec, ndd_rec_t *last){
        ndd_rec_t *r = malloc(sizeof(ndd_rec_t));
        if(r){
                memset(&r->brec, 0, sizeof(lnf_brec1_t));

                r->tcp_flags = 0;
                r->processed = 0;
                r->next = NULL;
                r->prev = NULL;
                if(last){
                        last->next = r;
                        r->prev = last;
                }

                *rec = r;
        }
}

int ndd_clear_old_rec(ndd_rec_t **r, uint64_t cutoff){
        int removed = 0;
        ndd_rec_t *tmp;

        while((*r)->brec.first < cutoff){
                tmp = (*r);
                if(!(*r)->next)
                        (*r) = NULL;
                else
                        (*r) = (*r)->next;
                free(tmp);
                removed++;
        }

        return removed;
}

/*
 * ndd_comm_t functions
 */

void ndd_init_comm(ndd_comm_t **c){
        ndd_comm_t *m = malloc(sizeof(ndd_comm_t));
        if(m){
                (*c) = m;
                (*c)->type = -1;
                (*c)->filter_id = 0;
                (*c)->message = NULL;
                (*c)->next = NULL;
                if(comm_bot == NULL){
                        comm_bot = (*c);
                        comm_top = (*c);
                }else{
                        comm_top->next = (*c);
                        comm_top = (*c);
                }
        }
}

void ndd_free_comm(ndd_comm_t *c){
        if(comm_bot == c)
                comm_bot = c->next;
        free(c->message);
        free(c);
        if(comm_bot == NULL)
                comm_top = NULL;
}

void ndd_fill_comm(char *string, int type, int filter_id){
        ndd_comm_t *c = NULL;

        pthread_mutex_lock(&comm_lock);
        ndd_init_comm(&c);

        c->message = strdup(string);
        c->type = type;
        c->time = time(NULL);
        c->filter_id = filter_id;
        pthread_mutex_unlock(&comm_lock);
}



/*
 * ndd_activef_t functions
 */

void ndd_init_activef(ndd_activef_t **a){
        ndd_activef_t *f = malloc(sizeof(ndd_activef_t));
        if(f){
                (*a) = f;
                f->filter = NULL;
                f->filter_string = NULL;
                f->tstart = 0;
                f->tstop = 0;
                f->next = NULL;
        }
}

void ndd_free_activef(ndd_activef_t *a){
        if(active_filters == a)
                active_filters = a->next;
        if(a->filter != NULL)
                lnf_filter_free(a->filter);
        if(a->filter_string != NULL)
                free(a->filter_string);
        free(a);
}


int ndd_add_active_filter(lnf_filter_t *flt, char *filter_string, uint64_t duration, char *table){
        pthread_mutex_lock(&active_filters_lock);
        uint64_t cur = (uint64_t)time(NULL);

        ndd_activef_t *new;
        ndd_init_activef(&new);
        new->filter = flt;
        new->filter_string = strdup(filter_string);
        new->tstart = cur;
        new->tstop = cur + duration;

        //remove old non-active filters
        ndd_activef_t *f = active_filters;
        ndd_activef_t *prev = NULL;
        while(f){
                if(f->tstop < (cur-60)){
                        ndd_activef_t *tmp = f;
                        f = f->next;

                        if(prev)
                                prev->next = f;

                        active_filters_count--;
                        ndd_free_activef(tmp);
                }
                prev = f;
                f = f->next;
        }

        //append new active filter
        if(!active_filters){
                active_filters = new;
        }else{
                f = active_filters;
                while(f->next){
                        f = f->next;
                }
                f->next = new;
        }
        active_filters_count++;

        write_stats = 1;
        pthread_mutex_unlock(&active_filters_lock);

        //add to db
        ndd_db_insert_active_filter(table, filter_string, new->tstart, new->tstop);

        return 0;
}

int ndd_get_active_filters(lnf_filter_t **l){
        //only get not expired filters
        ndd_activef_t *f = active_filters;
        uint64_t cur = (uint64_t)time(NULL);
        int i = 0;
        while(f){
                if(f->tstop < cur){
                        f = f->next;
                        continue;
                }

                l[i] = f->filter;
                i++;
                f = f->next;

        }
        return i;
}

void ndd_print_active_filters(FILE *stream){
        ndd_activef_t *f = active_filters;
        if(!f)
		return;
	fprintf(stream, "----------------------------------------\n");
        fprintf(stream, "ACTIVE-FILTERS--------------------------\n");
        int i = 0;
        uint64_t cur = (uint64_t)time(NULL);
        while(f){
                i++;
                fprintf(stream, "----------------------------------------\n");
                fprintf(stream, "Active-Filter (%d) : %s\n", i, f->filter_string);
                if(f->tstop < cur)
                        fprintf(stream, "Activity : NOT ACTIVE\n");
                else
                        fprintf(stream, "Activity : ACTIVE\n");
                char ts[20];
                time_t tm = (time_t)f->tstart;
                strftime(ts, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm));
                fprintf(stream, "       Time start : %s (%lu)\n", ts, f->tstart);
                tm = (time_t)f->tstop;
                strftime(ts, 20, "%Y-%m-%d %H:%M:%S", localtime(&tm));
                fprintf(stream, "       Time stop  : %s (%lu)\n", ts, f->tstop);
                f = f->next;
        }
}






