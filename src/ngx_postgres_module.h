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

#ifndef _NGX_POSTGRES_MODULE_H_
#define _NGX_POSTGRES_MODULE_H_

#include <assert.h>
#include <ngx_http.h>

extern ngx_module_t  ngx_postgres_module;


typedef struct {
    ngx_uint_t                          index;
    ngx_uint_t                          oid;
} ngx_postgres_param_t;

typedef struct {
    ngx_int_t                           column;
    ngx_int_t                           row;
    ngx_uint_t                          required;
    u_char                             *col_name;
} ngx_postgres_value_t;

typedef struct {
    ngx_http_variable_t                *variable;
    ngx_postgres_value_t                value;
    ngx_uint_t                          index;
} ngx_postgres_variable_t;

typedef struct ngx_postgres_rewrite_conf_s ngx_postgres_rewrite_conf_t;

typedef ngx_int_t (*ngx_postgres_rewrite_handler_pt) (ngx_http_request_t *, ngx_postgres_rewrite_conf_t *);

typedef struct {
    ngx_int_t                           status;
    ngx_str_t                           location;
    ngx_uint_t                          methods;
} ngx_postgres_rewrite_t;

struct ngx_postgres_rewrite_conf_s {
    ngx_array_t                        *methods; /* method-specific */
    ngx_postgres_rewrite_handler_pt     handler;
    ngx_postgres_rewrite_t             *rewrite;     /* default */
    ngx_uint_t                          key;
    ngx_uint_t                          methods_set;
};

typedef struct {
    in_port_t                           port;
    int                                 family;
    ngx_addr_t                         *addrs;
    ngx_str_t                           application_name;
    ngx_str_t                           dbname;
    ngx_str_t                           password;
    ngx_str_t                           user;
    ngx_uint_t                          naddrs;
} ngx_postgres_server_t;

static_assert(sizeof(ngx_postgres_server_t) <= sizeof(ngx_http_upstream_server_t), "sizeof(ngx_postgres_server_t) <= sizeof(ngx_http_upstream_server_t)");

typedef struct {
    ngx_str_t                           host;
    ngx_str_t                          *name;
    socklen_t                           socklen;
    struct sockaddr                    *sockaddr;
    u_char                             *connstring;
} ngx_postgres_peer_t;

typedef struct {
    ngx_postgres_peer_t                 peer[1];
    ngx_uint_t                          max_peer;
    ngx_uint_t                          single;
} ngx_postgres_peers_t;

typedef struct {
    ngx_flag_t                          prepare;
    ngx_flag_t                          reject;
    ngx_flag_t                          single;
    ngx_msec_t                          timeout;
    ngx_postgres_peers_t               *peers;
    ngx_queue_t                         busy;
    ngx_queue_t                         free;
    ngx_uint_t                          max_requests;
    ngx_uint_t                          max_save;
    ngx_uint_t                          peer;
    ngx_uint_t                          save;
} ngx_postgres_server_conf_t;

typedef struct {
    ngx_array_t                        *ids;
    ngx_array_t                        *params;
    ngx_flag_t                          listen;
    ngx_str_t                           sql;
    ngx_uint_t                          methods;
    ngx_uint_t                          percent;
} ngx_postgres_query_t;

typedef ngx_int_t (*ngx_postgres_output_handler_pt) (ngx_http_request_t *);

typedef struct {
    ngx_flag_t                          binary;
    ngx_flag_t                          header;
    ngx_flag_t                          string_quote_only;
    ngx_postgres_output_handler_pt      handler;
    ngx_str_t                           null;
    u_char                              delimiter;
    u_char                              escape;
    u_char                              quote;
} ngx_postgres_output_t;

typedef struct {
    ngx_http_complex_value_t           *complex_value;
    ngx_http_upstream_conf_t            upstream_conf;
} ngx_postgres_upstream_t;

typedef struct {
    ngx_array_t                        *methods; /* method-specific */
    ngx_array_t                        *rewrite_conf;
    ngx_array_t                        *variables;
    ngx_postgres_output_t               output;
    ngx_postgres_query_t               *query;     /* default */
    ngx_postgres_upstream_t             upstream;
    ngx_uint_t                          methods_set;
} ngx_postgres_location_conf_t;


#endif /* _NGX_POSTGRES_MODULE_H_ */
