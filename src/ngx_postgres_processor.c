/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ngx_postgres_ddebug.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_util.h"
#include "ngx_postgres_variable.h"

#include <stdbool.h>

void
ngx_postgres_process_events(ngx_http_request_t *r)
{
    ngx_postgres_upstream_peer_data_t  *pgdt;
    ngx_connection_t                   *pgxc;
    ngx_http_upstream_t                *u;
    ngx_int_t                           rc;

    dd("entering");

    u = r->upstream;
    pgxc = u->peer.connection;
    pgdt = u->peer.data;

    if (!ngx_postgres_upstream_is_my_peer(&u->peer)) {
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: trying to connect to something that"
                      " is not PostgreSQL database");

        goto failed;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "postgres: process events");

    switch (pgdt->state) {
    case state_db_connect:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "state_db_connect");
        rc = ngx_postgres_upstream_connect(r, pgxc, pgdt);
        break;
    case state_db_send_query:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "state_db_send_query");
        rc = ngx_postgres_upstream_send_query(r, pgxc, pgdt);
        break;
    case state_db_get_result:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "state_db_get_result");
        rc = ngx_postgres_upstream_get_result(r, pgxc, pgdt);
        break;
    case state_db_get_ack:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "state_db_get_ack");
        rc = ngx_postgres_upstream_get_ack(r, pgxc, pgdt);
        break;
    case state_db_idle:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "state_db_idle, re-using keepalive connection");
        pgxc->log->action = "sending query to PostgreSQL database";
        pgdt->state = state_db_send_query;
        rc = ngx_postgres_upstream_send_query(r, pgxc, pgdt);
        break;
    default:
        dd("unknown state:%d", pgdt->state);
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: unknown state:%d", pgdt->state);

        goto failed;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_postgres_upstream_finalize_request(r, u, rc);
    } else if (rc == NGX_ERROR) {
        goto failed;
    }

    dd("returning");
    return;

failed:

    ngx_postgres_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);

    dd("returning");
}

ngx_int_t
ngx_postgres_upstream_connect(ngx_http_request_t *r, ngx_connection_t *pgxc,
    ngx_postgres_upstream_peer_data_t *pgdt)
{
    PostgresPollingStatusType  pgrc;

    dd("entering");

    pgrc = PQconnectPoll(pgdt->pgconn);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "postgres: polling while connecting, rc:%d", (int) pgrc);

    if (pgrc == PGRES_POLLING_READING || pgrc == PGRES_POLLING_WRITING) {

        /*
         * Fix for Linux issue found by chaoslawful (via agentzh):
         * "According to the source of libpq (around fe-connect.c:1215), during
         *  the state switch from CONNECTION_STARTED to CONNECTION_MADE, there's
         *  no socket read/write operations (just a plain getsockopt call and a
         *  getsockname call). Therefore, for edge-triggered event model, we
         *  have to call PQconnectPoll one more time (immediately) when we see
         *  CONNECTION_MADE is returned, or we're very likely to wait for a
         *  writable event that has already appeared and will never appear
         *  again :)"
         */
        if (PQstatus(pgdt->pgconn) == CONNECTION_MADE && pgxc->write->ready) {
            dd("re-polling on connection made");

            pgrc = PQconnectPoll(pgdt->pgconn);
            dd("re-polling rc:%d", (int) pgrc);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                           "postgres: re-polling while connecting, rc:%d",
                           (int) pgrc);

            if (pgrc == PGRES_POLLING_READING || pgrc == PGRES_POLLING_WRITING)
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                               "postgres: busy while connecting, rc:%d",
                               (int) pgrc);

                dd("returning NGX_AGAIN");
                return NGX_AGAIN;
            }

            goto done;
        }

#if defined(DDEBUG) && (DDEBUG)
        switch (PQstatus(pgdt->pgconn)) {
        case CONNECTION_NEEDED:
             dd("connecting (waiting for connect()))");
             break;
        case CONNECTION_STARTED:
             dd("connecting (waiting for connection to be made)");
             break;
        case CONNECTION_MADE:
             dd("connecting (connection established)");
             break;
        case CONNECTION_AWAITING_RESPONSE:
             dd("connecting (credentials sent, waiting for response)");
             break;
        case CONNECTION_AUTH_OK:
             dd("connecting (authenticated)");
             break;
        case CONNECTION_SETENV:
             dd("connecting (negotiating envinroment)");
             break;
        case CONNECTION_SSL_STARTUP:
             dd("connecting (negotiating SSL)");
             break;
        default:
             /*
              * This cannot happen, PQconnectPoll would return
              * PGRES_POLLING_FAILED in that case.
              */
             dd("connecting (unknown state:%d)", (int) PQstatus(pgdt->pgconn));

             dd("returning NGX_ERROR");
             return NGX_ERROR;
        }
#endif /* DDEBUG */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                       "postgres: busy while connecting, rc:%d", (int) pgrc);

        dd("returning NGX_AGAIN");
        return NGX_AGAIN;
    }

done:

    /* remove connection timeout from new connection */
    if (pgxc->write->timer_set) {
        ngx_del_timer(pgxc->write);
    }

    if (pgrc != PGRES_POLLING_OK) {
        dd("connection failed");
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: connection failed: %s",
                      PQerrorMessage(pgdt->pgconn));

        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    dd("connected successfully");
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "postgres: connected successfully");

    pgxc->log->action = "sending query to PostgreSQL database";
    pgdt->state = state_db_send_query;

    dd("returning");
    return ngx_postgres_upstream_send_query(r, pgxc, pgdt);
}


bool is_variable_character(char *p) {
    return ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') || *p == '_');
}
char * find_query_in_json(ngx_http_request_t *r, u_char *data, ngx_int_t length) {
    //fprintf(stdout, "Looking for %s\n", data);

    u_char *p = data;


    ngx_str_t meta_variable = ngx_string("meta");
    ngx_uint_t meta_variable_hash = ngx_hash_key(meta_variable.data, meta_variable.len);
    ngx_http_variable_value_t *raw_meta = ngx_http_get_variable( r, &meta_variable, meta_variable_hash  );

    u_char *m = raw_meta->data;
    //fprintf(stdout, "Looking for %s\n", data);
    //fprintf(stdout, "Looking for %s\n", raw_meta->data);
    for (; m < raw_meta->data + raw_meta->len; m++) {
        if (*m == '"') {
            ngx_int_t i = 0;


            for (; i < length - 2; i++)
                if (*(m + 1 + i) != *(p + i + 1))
                    break;


            if (i == length - 2 && *(m + i + 1) == '"') {


                u_char *j = m + i + 4;
                while (*j != '"' && *j != '\0') {
                    if (*j == '\\') {
                        j++;
                    }
                    j++;
                }

                u_char *c = m + i + 4;

                int written = 0;


                char *query = ngx_pnalloc(r->pool, j - c + 1);
                if (query == NULL) {
                    dd("returning NGX_ERROR");
                    return NULL;
                }


                while (c < j) {
                    if (*c == '$') {
                        u_char *z = c + 1;
                        while (is_variable_character((char*)z))
                            z++;


                        ngx_str_t url_variable;

                        url_variable.data = c + 1;
                        url_variable.len = z - (c + 1);

//                        fprintf(stdout, "replacing variable in sql query %s \n %d \n", c + 1, z - (c + 1));

                        ngx_str_t param_variable = url_variable;
                        ngx_uint_t param_variable_hash = ngx_hash_key(param_variable.data, param_variable.len);
                        ngx_http_variable_value_t *raw_param = ngx_http_get_variable( r, &param_variable, param_variable_hash  );


                        ngx_uint_t k;
                        for (k = 0; k < raw_param->len; k++) {
                            query[written++] = raw_param->data[k];
                        }
                        c = z;
                        continue;

                    } else if (*c == '\\' && *(c + 1) == 'u') {
                        if (*(c + 2) == '0' && *(c + 3) == '0' && *(c + 4) == '0' && *(c + 5) == 'A') {
                            query[written++] = '\n';
                            c += 5;
                        }
                    } else {
                        query[written++] = *c;
                    }
                    c++;
                }
                query[written] = '\0';

                //fprintf(stdout, "query is now %s", query);
                return query;

            }
        }
    }
    return NULL;
}

int generate_prepared_query(ngx_http_request_t *r, char *query, u_char *data, int len, int *paramnum, Oid *types, char **values, char **names) {
    // compute size for placeholders
    u_char *p = data;
    int size = len;
    if (query == NULL) {
        for (; p < data + len; p++) {
            if (*p == ':' && (is_variable_character((char*)(p + 1)) || *(p + 1) == ':' ||  *(p + 1) == '@')) {
                // leave double colon as is
                if (*(p + 1) == ':') {
                    p++;
                // :@:query denotes subquery partial
                } else if (*(p + 2) == ':' && *(p + 1) == '@') {
                    size -= 2; // :t
                    p += 2;

                    u_char *f = p + 1;
                    while (is_variable_character((char*)f))
                        f++;
                    size -= f - p - 1; // :name

                    //fprintf(stdout, "Length is %d %s\n", f - p, p);
                    char *subquery = find_query_in_json(r, p, f - p + 1);

                    int newsize = generate_prepared_query(r, NULL, (u_char *) subquery, strlen(subquery), paramnum, types, values, names);
                    size += newsize; // expanded :sql
                } else {
                    // typed param
                    if (*(p + 2) == ':') {
                        size -= 2; // :t
                        p += 2;
                    }
                    u_char *f = p + 1;
                    while (is_variable_character((char*)f))
                        f++;
                    size -= f - p; // :name

                    int i = 0;
                    for (; i < *paramnum; i++) {
                        if (strncmp(names[i], (char *) p, f - p) == 0
                        && !is_variable_character(names[i] + (f - p))) {
                            break;
                        }
                    }
                    if (i == *paramnum) {
                        names[*paramnum] = (char *) p;
                        (*paramnum)++;
                    }
                    char placeholder_name[16];
                    sprintf(placeholder_name, "$%d", i + 1);
                    size += strlen(placeholder_name); // $1


                }

            }
        }
        //fprintf(stdout, "Final query size: [%d]\n", size);
    } else {
        u_char *lastcut = data;
        int counter = 0;
        for (; p < data + len; p++) {
            if (*p == ':' && (is_variable_character((char*)(p + 1)) || *(p + 1) == ':' || *(p + 1) == '@')) {
                if (*(p + 1) == ':') {
                    p++;
                    continue;
                }


                // copy left side
                memcpy(query + counter, lastcut, p - lastcut);
                counter += p - lastcut;

                // partial
                if (*(p + 2) == ':' && *(p + 1) == '@') {
                    p += 2;

                    u_char *f = p + 1;
                    while (is_variable_character((char*)f))
                        f++;

                    //fprintf(stdout, "Length is %d %s\n", f - p, p);
                    char *subquery = find_query_in_json(r, p, f - p + 1);

                    // copy middle side
                    counter += generate_prepared_query(r, query + counter, (u_char *) subquery, strlen(subquery), paramnum, types, values, names);


                    //fprintf(stdout, "Query after subquery %s\n", query);
                    lastcut = f;
                    //fprintf(stdout, "Final TO RUN :%s %d\n", query, strlen(subquery));

                // typed param
                } else {
                    int type = 0;
                    if (*(p + 2) == ':') {
                        switch (*(p + 1)) {
                            case 't': case 's':
                                type = 25;
                                break;
                            case 'd': case 'i': case 'n':
                                type = 23;
                                break;
                            case 'f':
                                type = 701;
                                break;
                            case 'b':
                                type = 16;
                                break;
                            case 'j':
                                type = 114;
                                break;
                            default:
                                type = 0;
                        }
                        p += 2;
                    } else { // default is string
                        type = 25;
                    }

                    u_char *f = p + 1;
                    while (is_variable_character((char*)f))
                        f++;


                    int i = 0;
                    for (; i < *paramnum; i++) {
                        if (strncmp(names[i], (char *) p, f - p) == 0
                        && !is_variable_character(names[i] + (f - p))) {
                            break;
                        }
                    }
                    if (i == *paramnum) {

                        ngx_str_t param_variable;
                        param_variable.data = p + 1;
                        param_variable.len = f - (p + 1);

                        //fprintf(stdout, "req param by name: [%s] %d\n", param_variable.data, param_variable.len);
                        ngx_uint_t param_hash = ngx_hash_key(param_variable.data, param_variable.len);
                        ngx_http_variable_value_t *param_value = ngx_http_get_variable( r, &param_variable, param_hash  );

                        if (param_value != NULL && !param_value->not_found) {
                            char *final_value = ngx_palloc(r->pool, (param_value->len) + 1);
                            strncpy(final_value, (char *) param_value->data, param_value->len);
                            strncpy(final_value + (param_value->len), "\0", 1);
                            values[*paramnum] = final_value;
                        } else {
                            values[*paramnum] = NULL;
                        }
                        names[*paramnum] = (char *) p;
                        types[*paramnum] = type;
                        (*paramnum)++;
                    }


                    // add placeholder
                    char placeholder_name[16];
                    sprintf(placeholder_name, "$%d", i + 1);
                    memcpy(query + counter, placeholder_name, strlen(placeholder_name));
                    counter += strlen(placeholder_name);

                    lastcut = f;

                    //fprintf(stdout, "Query after param %d %s\n", counter, query);

                // untyped subquery
                }
            }
        }
        memcpy(query + counter, lastcut, data + len - lastcut + 1);
        counter += data + len - lastcut;
        memcpy(query + counter, "\0", 1);
        //fprintf(stdout, "Final query: [%d/%d/%d] [%lu] %s\n", strlen(query), size, counter, strlen(query), query);
        return counter;
    }
    //fprintf(stdout, "Paramnum is %d\n", paramnum);
    return size;
}

ngx_int_t
ngx_postgres_upstream_send_query(ngx_http_request_t *r, ngx_connection_t *pgxc,
    ngx_postgres_upstream_peer_data_t *pgdt)
{
    ngx_postgres_loc_conf_t  *pglcf;
    ngx_int_t                 pgrc;
    u_char                   *query;

    dd("entering");

    pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);



    u_char *p = pgdt->query.data;
    // run query substitution
    if (*p == ':') {
        // prepare param arrays
        Oid *types[30];
        Oid *Types = (Oid *) types;

        const char *Values[30];
        const char *Names[30];

        // when query is :index, set $action to and read $sql
        u_char *start = pgdt->query.data + 1;
        int len = pgdt->query.len - 1;
        int i = 0;
        while (*(start + i) >= 'a' && *(start + i) <= 'z' && i < len) {
            if (i == len - 1) {
                ngx_str_t meta_variable = ngx_string("action");
                ngx_uint_t meta_variable_hash = ngx_hash_key(meta_variable.data, meta_variable.len);
                ngx_http_variable_value_t *meta_data = ngx_http_get_variable( r, &meta_variable, meta_variable_hash  );
                meta_data->data = start;
                meta_data->len = len;

                ngx_str_t sql_variable = ngx_string("sql");
                ngx_uint_t sql_variable_hash = ngx_hash_key(sql_variable.data, sql_variable.len);
                ngx_http_variable_value_t *sql_data = ngx_http_get_variable( r, &sql_variable, sql_variable_hash  );

                start = sql_data->data;
                len = sql_data->len;
                break;
            }
            i++;
        }

        // measure and alloc new query
        int paramnum = 0;
        int prepared_query_size = generate_prepared_query(r, NULL, start, len, &paramnum, NULL, NULL, (char **) &Names);
        //fprintf(stdout, "prepared query size: %d \n", prepared_query_size);
        query = ngx_pnalloc(r->pool, prepared_query_size + 1);


        // generate prepared query
        paramnum = 0;
        generate_prepared_query(r, (char *) query, start, len, &paramnum, Types, (char **) &Values, (char **) &Names);
        //fprintf(stdout, "prepared query: [%d] %s \n", paramnum, query);

        //for (int i = 0; i < paramnum; i++)
        //    fprintf(stdout, "Prepared param #%d [%d] %s %p \n", i, Types[i], Values[i], Values[i]);
        if (pgdt->statements) {
            // hash query
            ngx_uint_t prepared_hash = ngx_hash_key(query, strlen((char *) query));
            char *prepared_name = ngx_pnalloc(r->pool, 32);
            sprintf(prepared_name, "test%lu", ( unsigned long )prepared_hash);

            // find if query was prepared for this connection
            ngx_uint_t n = 0;
            int matched = 0;
            for (; n < 256 && pgdt->statements[n]; n++) {
                if (pgdt->statements[n] == prepared_hash) {
                    matched = 1;
                    //fprintf(stdout, "Found prepared query %s %lu\n", query, n);
                    break;
                } else {
                    //fprintf(stdout, "%d != %d\n", *(pgdt->statements + n), prepared_hash);
                }
            }
            //fprintf(stdout, "statements [%p]\n", pgdt->statements);

            // prepare query synchronously the first time
            if (matched == 0) {
               //fprintf(stdout, "Preparing query [%d] %s\n", n, query);

                PQprepare(pgdt->pgconn,
                                    prepared_name,
                                    (char *) query,
                                    paramnum,
                                    Types);
                pgdt->statements[n] = prepared_hash;
                //fprintf(stdout, "Preparing query [%d] %d\n",n, prepared_hash);

            }

            pgrc = PQsendQueryPrepared(pgdt->pgconn,
                             prepared_name,
                             paramnum,(const char** )Values,NULL,NULL,0);

            dd("Sent query prepared");
        } else {
            pgrc = PQsendQueryParams(pgdt->pgconn, (const char *) query, paramnum, Types, (const char** )Values, NULL, NULL, 0);
            //fprintf(stdout, "Sent query unprepared [%d] \n", pgrc);
        }
    } else {

        //fprintf(stdout, "standart QUERY TO RUN : %s\n", pgdt->query.data);

        query = ngx_pnalloc(r->pool, pgdt->query.len + 1);
        if (query == NULL) {
            dd("returning NGX_ERROR");
            return NGX_ERROR;
        }

        (void) ngx_cpystrn(query, pgdt->query.data, pgdt->query.len + 1);


        dd("sending query: %s", query);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                       "postgres: sending query: \"%s\"", query);

        if (pglcf->output_binary) {
            pgrc = PQsendQueryParams(pgdt->pgconn, (const char *) query,
                                     0, NULL, NULL, NULL, NULL, /* binary */ 1);
        } else {
            pgrc = PQsendQuery(pgdt->pgconn, (const char *) query);
        }
    }

    if (pgrc == 0) {
        dd("sending query failed");
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: sending query failed: %s",
                      PQerrorMessage(pgdt->pgconn));

        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    /* set result timeout */
    ngx_add_timer(pgxc->read, r->upstream->conf->read_timeout);

    dd("query sent successfully");
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "postgres: query sent successfully");

    pgxc->log->action = "waiting for result from PostgreSQL database";
    pgdt->state = state_db_get_result;

    dd("returning NGX_DONE");
    return NGX_DONE;
}

ngx_int_t
ngx_postgres_upstream_get_result(ngx_http_request_t *r, ngx_connection_t *pgxc,
    ngx_postgres_upstream_peer_data_t *pgdt)
{
    ExecStatusType   pgrc;
    PGresult        *res;
    ngx_int_t        rc;

    dd("entering");

    /* remove connection timeout from re-used keepalive connection */
    if (pgxc->write->timer_set) {
        ngx_del_timer(pgxc->write);
    }

    if (!PQconsumeInput(pgdt->pgconn)) {
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: failed to consume input: %s",
                      PQerrorMessage(pgdt->pgconn));

        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    if (PQisBusy(pgdt->pgconn)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                       "postgres: busy while receiving result");

        dd("returning NGX_AGAIN");
        return NGX_AGAIN;
    }

    dd("receiving result");

    res = PQgetResult(pgdt->pgconn);
    if (res == NULL) {
        dd("receiving result failed");
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: failed to receive result: %s",
                      PQerrorMessage(pgdt->pgconn));

        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    pgrc = PQresultStatus(res);
    if ((pgrc != PGRES_COMMAND_OK) && (pgrc != PGRES_TUPLES_OK)) {
        dd("receiving result failed");
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: failed to receive result: %s: %s",
                      PQresStatus(pgrc),
                      PQerrorMessage(pgdt->pgconn));

        PQclear(res);

        dd("returning NGX_HTTP_INTERNAL_SERVER_ERROR");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dd("result received successfully, cols:%d rows:%d",
       PQnfields(res), PQntuples(res));

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pgxc->log, 0,
                   "postgres: result received successfully, cols:%d rows:%d",
                   PQnfields(res), PQntuples(res));

    pgxc->log->action = "processing result from PostgreSQL database";
    rc = ngx_postgres_process_response(r, res);

    PQclear(res);

    if (rc != NGX_DONE) {
        dd("returning rc:%d", (int) rc);
        return rc;
    }

    dd("result processed successfully");

    pgxc->log->action = "waiting for ACK from PostgreSQL database";
    pgdt->state = state_db_get_ack;

    dd("returning");
    return ngx_postgres_upstream_get_ack(r, pgxc, pgdt);
}

ngx_int_t
ngx_postgres_process_response(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_loc_conf_t      *pglcf;
    ngx_postgres_ctx_t           *pgctx;
    ngx_postgres_rewrite_conf_t  *pgrcf;
    ngx_postgres_variable_t      *pgvar;
    ngx_str_t                    *store;
    char                         *affected;
    size_t                        affected_len;
    ngx_uint_t                    i;
    ngx_int_t                     rc;

    dd("entering");

    pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    /* set $postgres_columns */
    pgctx->var_cols = PQnfields(res);

    /* set $postgres_rows */
    pgctx->var_rows = PQntuples(res);

    pgctx->res = res;

    /* set $postgres_affected */
    if (ngx_strncmp(PQcmdStatus(res), "SELECT", sizeof("SELECT") - 1)) {
        affected = PQcmdTuples(res);
        affected_len = ngx_strlen(affected);
        if (affected_len) {
            pgctx->var_affected = ngx_atoi((u_char *) affected, affected_len);
        }
    }

    if (pglcf->rewrites) {
        /* process rewrites */
        pgrcf = pglcf->rewrites->elts;
        for (i = 0; i < pglcf->rewrites->nelts; i++) {
            rc = pgrcf[i].handler(r, &pgrcf[i]);
            if (rc != NGX_DECLINED) {
                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    dd("returning NGX_DONE, status %d", (int) rc);
                    pgctx->status = rc;
                    pgctx->res = NULL;
                    return NGX_DONE;
                }

                pgctx->status = rc;
                break;
            }
        }
    }

    pgctx->res = NULL;

    if (pglcf->variables) {
        /* set custom variables */
        pgvar = pglcf->variables->elts;
        store = pgctx->variables->elts;

        for (i = 0; i < pglcf->variables->nelts; i++) {
            store[i] = ngx_postgres_variable_set_custom(r, res, &pgvar[i]);
            if ((store[i].len == 0) && (pgvar[i].value.required)) {
                dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
                pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_DONE;
            }
        }
    }

    if (pglcf->output_handler) {
        /* generate output */
        dd("returning");
        return pglcf->output_handler(r, res);
    }

    dd("returning NGX_DONE");
    return NGX_DONE;
}

ngx_int_t
ngx_postgres_upstream_get_ack(ngx_http_request_t *r, ngx_connection_t *pgxc,
    ngx_postgres_upstream_peer_data_t *pgdt)
{
    PGresult  *res;

    dd("entering");

    if (!PQconsumeInput(pgdt->pgconn)) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    if (PQisBusy(pgdt->pgconn)) {
        dd("returning NGX_AGAIN");
        return NGX_AGAIN;
    }

    /* remove result timeout */
    if (pgxc->read->timer_set) {
        ngx_del_timer(pgxc->read);
    }

    dd("receiving ACK (ready for next query)");

    res = PQgetResult(pgdt->pgconn);
    if (res != NULL) {
        dd("receiving ACK failed");
        ngx_log_error(NGX_LOG_ERR, pgxc->log, 0,
                      "postgres: receiving ACK failed: multiple queries(?)");

        PQclear(res);

        dd("returning NGX_HTTP_INTERNAL_SERVER_ERROR");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dd("ACK received successfully");

    pgxc->log->action = "being idle on PostgreSQL database";
    pgdt->state = state_db_idle;

    dd("returning");
    return ngx_postgres_upstream_done(r, r->upstream, pgdt);
}

ngx_int_t
ngx_postgres_upstream_done(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_postgres_upstream_peer_data_t *pgdt)
{
    ngx_postgres_ctx_t  *pgctx;

    dd("entering");

    /* flag for keepalive */
    u->headers_in.status_n = NGX_HTTP_OK;

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    if (pgctx->status >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_postgres_upstream_finalize_request(r, u, pgctx->status);
    } else {
        ngx_postgres_upstream_finalize_request(r, u, NGX_OK);
    }

    dd("returning NGX_DONE");
    return NGX_DONE;
}
