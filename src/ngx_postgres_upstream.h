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

#ifndef _NGX_HTTP_UPSTREAM_POSTGRES_H_
#define _NGX_HTTP_UPSTREAM_POSTGRES_H_

#include <libpq-fe.h>
#include <ngx_http.h>

typedef enum {
    state_db_connect,
    state_db_send_prepare,
    state_db_send_query,
    state_db_get_result,
    state_db_get_ack,
    state_db_idle
} ngx_postgres_state_t;

typedef struct {
    ngx_queue_t                        queue;
    ngx_uint_t                         hash;
} ngx_postgres_prepare_t;

typedef struct {
    const char                        **keywords;
    const char                        **values;
    ngx_str_t                           host;
    ngx_str_t                          *name;
    socklen_t                           socklen;
    struct sockaddr                    *sockaddr;
    u_char                             *value;
} ngx_postgres_peer_t;

typedef struct {
    ngx_flag_t                          ignore;
    ngx_flag_t                          prepare;
    ngx_flag_t                          single;
    ngx_msec_t                          timeout;
    ngx_postgres_peer_t                *peers;
    ngx_queue_t                         busy;
    ngx_queue_t                         free;
    ngx_uint_t                          max_requests;
    ngx_uint_t                          max_save;
    ngx_uint_t                          npeers;
    ngx_uint_t                          peer;
    ngx_uint_t                          save;
} ngx_postgres_server_conf_t;

typedef struct {
    ngx_array_t                       *listen;
    ngx_connection_t                  *connection;
    ngx_postgres_server_conf_t        *server_conf;
    ngx_postgres_state_t               state;
    ngx_queue_t                       *prepare;
    ngx_str_t                          charset;
    ngx_str_t                         *name;
    ngx_uint_t                         requests;
    PGconn                            *conn;
    socklen_t                          socklen;
    struct sockaddr                   *sockaddr;
} ngx_postgres_common_t;

typedef struct {
    ngx_str_t                          cmdStatus;
    ngx_str_t                          cmdTuples;
    ngx_int_t                          nfields;
    ngx_int_t                          ntuples;
    PGresult                          *res;
} ngx_postgres_result_t;

typedef struct {
    ngx_array_t                       *variables;
    ngx_chain_t                       *response;
    ngx_flag_t                         failed;
    ngx_http_request_t                *request;
    ngx_int_t                          status;
    ngx_postgres_common_t              common;
    ngx_postgres_result_t              result;
    ngx_str_t                          sql;
    ngx_uint_t                         hash;
    ngx_uint_t                         nParams;
    ngx_uint_t                         resultFormat;
    Oid                               *paramTypes;
    u_char                           **paramValues;
    u_char                            *stmtName;
} ngx_postgres_data_t;

typedef struct {
    ngx_event_t                        timeout;
    ngx_postgres_common_t              common;
    ngx_queue_t                        queue;
} ngx_postgres_save_t;

char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *PQerrorMessageMy(const PGconn *conn);
char *PQresultErrorMessageMy(const PGresult *res);
ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *);
ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool);
ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool);
ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf);
void ngx_postgres_free_connection(ngx_postgres_common_t *, ngx_postgres_common_t *, ngx_flag_t);

#endif /* _NGX_HTTP_UPSTREAM_POSTGRES_H_ */
