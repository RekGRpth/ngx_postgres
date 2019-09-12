/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
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

#include <libpq-fe.h>

#include "ngx_postgres_escape.h"
#include "ngx_postgres_module.h"


uintptr_t ngx_postgres_script_exit_code = (uintptr_t) NULL;


void ngx_postgres_escape_string(ngx_http_script_engine_t *e) {
    ngx_postgres_escape_t *pge;
    pge = (ngx_postgres_escape_t *) e->ip;
    e->ip += sizeof(ngx_postgres_escape_t);
    ngx_http_variable_value_t *v = e->sp - 1;
    if (!v || v->not_found) { ngx_str_set(v, "NULL"); goto done; }
    if (!v->len) {
        if (pge->empty) { ngx_str_set(v, "''"); goto done; }
        else { ngx_str_set(v, "NULL"); goto done; }
    }
    u_char *p = ngx_pnalloc(e->request->pool, 2 * v->len + 2);
    if (!p) {
        e->ip = (u_char *) &ngx_postgres_script_exit_code;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }
    u_char *s = p;
    *p++ = '\'';
    v->len = PQescapeString((char *) p, (const char *) v->data, v->len);
    p[v->len] = '\'';
    v->len += 2;
    v->data = s;
done:
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
}
