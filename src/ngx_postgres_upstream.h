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

#include "ngx_postgres_module.h"


typedef enum {
    state_db_connect,
    state_db_send_prepare,
    state_db_send_query,
    state_db_get_result,
    state_db_get_ack,
    state_db_idle
} ngx_postgres_state_t;

typedef struct {
    ngx_uint_t                         hash;
    ngx_uint_t                         used;
} ngx_postgres_statement_t;

typedef struct {
    int                                nParams;
    ngx_http_request_t                *request;
    ngx_postgres_server_conf_t        *server_conf;
    ngx_postgres_statement_t          *statements;
    ngx_postgres_state_t               state;
    ngx_str_t                         *name;
    ngx_uint_t                         hash;
    ngx_uint_t                         resultFormat;
    Oid                               *paramTypes;
    PGconn                            *conn;
    socklen_t                          socklen;
    struct sockaddr                   *sockaddr;
    u_char                            *command;
    u_char                           **paramValues;
    u_char                            *stmtName;
    unsigned                           failed;
} ngx_postgres_peer_data_t;

typedef struct {
    ngx_connection_t                  *connection;
    ngx_postgres_server_conf_t        *server_conf;
    ngx_postgres_statement_t          *statements;
    ngx_queue_t                        queue;
    ngx_str_t                         *name;
    PGconn                            *conn;
    socklen_t                          socklen;
    struct sockaddr                   *sockaddr;
} ngx_postgres_cached_t;

typedef struct {
    ngx_array_t                       *variables;
    ngx_chain_t                       *response;
    ngx_int_t                          cmdTuples;
    ngx_int_t                          nfields;
    ngx_int_t                          ntuples;
    ngx_int_t                          status;
    ngx_str_t                          sql;
    PGresult                          *res;
} ngx_postgres_context_t;


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *);
ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool);
ngx_int_t ngx_postgres_init_upstream(ngx_conf_t *, ngx_http_upstream_srv_conf_t *);
void ngx_postgres_free_connection(ngx_connection_t *, PGconn *, ngx_postgres_server_conf_t *);


#endif /* _NGX_HTTP_UPSTREAM_POSTGRES_H_ */
