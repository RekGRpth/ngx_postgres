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

#include "ngx_postgres_module.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


ngx_int_t ngx_postgres_variable_nfields(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    v->not_found = 1;
    if (!pd) return NGX_OK;
    if (!(v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_sprintf(v->data, "%i", PQnfields(pd->res)) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_ntuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    v->not_found = 1;
    if (!pd) return NGX_OK;
    if (!(v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_sprintf(v->data, "%i", PQntuples(pd->res)) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_cmdtuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    v->not_found = 1;
    if (!pd) return NGX_OK;
    if (!(v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    v->len = ngx_sprintf(v->data, "%s", PQcmdTuples(pd->res)) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_query(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    v->not_found = 1;
    if (!pd || !pd->sql.len) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = pd->sql.len;
    v->data = pd->sql.data;
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    v->not_found = 1;
    if (!pd || !pd->variables) return NGX_OK;
    ngx_str_t *store = pd->variables->elts;
    ngx_postgres_variable_t *variable = (ngx_postgres_variable_t *) data; /* index is always valid */
    if (!store[variable->index].len) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = store[variable->index].len;
    v->data = store[variable->index].data;
    return NGX_OK;
}


ngx_str_t ngx_postgres_variable_set(ngx_http_request_t *r, ngx_postgres_variable_t *variable) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_int_t col;
    ngx_str_t value = ngx_null_string;
    ngx_postgres_value_t *pgv = &variable->value;
    if (pgv->col != NGX_ERROR) /* get col by number */ col = pgv->col; else { /* get col by name */
        col = PQfnumber(pd->res, (const char *)pgv->name);
        if (col == NGX_ERROR) {
            if (pgv->required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value from col \"%s\" that wasn't found in the received result-set in location \"%V\"", &variable->variable->name, pgv->name, &core_loc_conf->name);
            }
            return value;
        }
    }
    if (pgv->row >= PQntuples(pd->res) || col >= PQnfields(pd->res)) {
        if (pgv->required) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value out of range of the received result-set (rows:%d cols:%d) in location \"%V\"", &variable->variable->name, PQntuples(pd->res), PQnfields(pd->res), &core_loc_conf->name);
        }
        return value;
    }
    if (PQgetisnull(pd->res, pgv->row, col)) {
        if (pgv->required) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-NULL value in location \"%V\"", &variable->variable->name, &core_loc_conf->name);
        }
        return value;
    }
    ngx_int_t len = PQgetlength(pd->res, pgv->row, col);
    if (!len) {
        if (pgv->required) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-zero length value in location \"%V\"", &variable->variable->name, &core_loc_conf->name);
        }
        return value;
    }
    if (!(value.data = ngx_pnalloc(r->pool, len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return value; }
    ngx_memcpy(value.data, PQgetvalue(pd->res, pgv->row, col), len);
    value.len = len;
    return value;
}
