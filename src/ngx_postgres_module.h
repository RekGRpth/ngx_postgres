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
    ngx_array_t                        *ids;
    ngx_array_t                        *params;
    ngx_flag_t                          listen;
    ngx_str_t                           sql;
    ngx_uint_t                          percent;
} ngx_postgres_query_t;

typedef ngx_int_t (*ngx_postgres_output_handler_pt) (ngx_http_request_t *);

typedef struct {
    ngx_flag_t                          binary;
    ngx_flag_t                          header;
    ngx_flag_t                          string;
    ngx_postgres_output_handler_pt      handler;
    ngx_str_t                           null;
    u_char                              delimiter;
    u_char                              escape;
    u_char                              quote;
} ngx_postgres_output_t;

typedef struct {
    ngx_array_t                        *variables;
    ngx_http_complex_value_t           *complex;
    ngx_http_upstream_conf_t            upstream;
    ngx_postgres_output_t               output;
    ngx_postgres_query_t               *query;
} ngx_postgres_location_conf_t;


#endif /* _NGX_POSTGRES_MODULE_H_ */
