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

#include <ngx_http.h>


extern ngx_module_t  ngx_postgres_module;


typedef struct {
    ngx_http_script_code_pt             code;
    ngx_uint_t                          empty;
} ngx_postgres_escape_t;

typedef struct {
    ngx_uint_t                          oid;
    ngx_uint_t                          index;
} ngx_postgres_arg_t;

typedef struct {
    ngx_uint_t                          methods;
    ngx_str_t                           sql;
    ngx_array_t                         args;
} ngx_postgres_query_t;

typedef struct {
    ngx_uint_t                          methods;
    ngx_int_t                           status;
    ngx_str_t                           location;
} ngx_postgres_rewrite_t;

typedef struct {
    ngx_int_t                           row;
    ngx_int_t                           column;
    u_char                             *col_name;
    ngx_uint_t                          required;
} ngx_postgres_value_t;

typedef struct {
    ngx_uint_t                          idx;
    ngx_http_variable_t                *var;
    ngx_postgres_value_t                value;
} ngx_postgres_variable_t;

typedef struct ngx_postgres_rewrite_conf_s ngx_postgres_rewrite_conf_t;

typedef ngx_int_t (*ngx_postgres_rewrite_handler_pt) (ngx_http_request_t *, ngx_postgres_rewrite_conf_t *);

struct ngx_postgres_rewrite_conf_s {
    /* condition */
    ngx_uint_t                          key;
    ngx_postgres_rewrite_handler_pt     handler;
    /* methods */
    ngx_uint_t                          methods_set;
    ngx_array_t                         methods; /* method-specific */
    ngx_postgres_rewrite_t             *def;     /* default */
};

typedef ngx_int_t (*ngx_postgres_output_handler_pt) (ngx_http_request_t *);

typedef struct {
    ngx_addr_t                         *addrs;
    ngx_uint_t                          naddrs;
    in_port_t                           port;
    int                                 family;
    ngx_str_t                           dbname;
    ngx_str_t                           user;
    ngx_str_t                           password;
    ngx_str_t                           application_name;
} ngx_postgres_server_t;

typedef struct {
    struct sockaddr                    *sockaddr;
    socklen_t                           socklen;
    ngx_str_t                           name;
    ngx_str_t                           host;
    u_char                             *connstring;
} ngx_postgres_peer_t;

typedef struct {
    ngx_uint_t                          single;
    ngx_uint_t                          number;
    ngx_postgres_peer_t                 peer[1];
} ngx_postgres_peers_t;

typedef struct {
    ngx_postgres_peers_t               *peers;
    ngx_uint_t                          current;
    /* keepalive */
    ngx_flag_t                          single;
    ngx_queue_t                         free;
    ngx_queue_t                         cache;
    ngx_uint_t                          active_conns;
    ngx_uint_t                          max_cached;
    ngx_uint_t                          max_statements;
    ngx_uint_t                          reject;
} ngx_postgres_server_conf_t;

typedef struct {
    ngx_uint_t                          hash;
    ngx_uint_t                          used;
} ngx_postgres_statement_t;

typedef struct {
    /* upstream */
    ngx_http_upstream_conf_t            upstream;
    ngx_http_complex_value_t           *upstream_cv;
    /* queries */
    ngx_uint_t                          methods_set;
    ngx_array_t                         methods; /* method-specific */
    ngx_postgres_query_t               *def;     /* default */
    /* rewrites */
    ngx_array_t                        *rewrite_conf;
    /* output */
    ngx_postgres_output_handler_pt      output_handler;
    unsigned                            output_binary:1;
    /* custom variables */
    ngx_array_t                        *variables;
} ngx_postgres_location_conf_t;


#endif /* _NGX_POSTGRES_MODULE_H_ */
