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


static ngx_int_t ngx_postgres_variable_nfields(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
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


static ngx_int_t ngx_postgres_variable_ntuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
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


static ngx_int_t ngx_postgres_variable_cmdtuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
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


static ngx_int_t ngx_postgres_variable_query(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
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
    ngx_str_t *elts = pd->variables->elts;
    ngx_uint_t index = *(ngx_uint_t *)data;
    if (!elts[index].len) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = elts[index].len;
    v->data = elts[index].data;
    return NGX_OK;
}


typedef struct {
    ngx_http_variable_t                *variable;
    ngx_int_t                           col;
    ngx_int_t                           row;
    ngx_uint_t                          required;
    u_char                             *name;
} ngx_postgres_variable_t;


ngx_int_t ngx_postgres_variable_set(ngx_http_request_t *r) {
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (!location_conf->variables) return NGX_OK;
    ngx_postgres_variable_t *variable = location_conf->variables->elts;
    ngx_str_t *elts = pd->variables->elts;
    for (ngx_uint_t i = 0; i < location_conf->variables->nelts; i++) {
        if (variable[i].col == NGX_ERROR) {
            if ((variable[i].col = PQfnumber(pd->res, (const char *)variable[i].name)) == -1) {
                if (variable[i].required) {
                    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value from col \"%s\" that wasn't found in the received result-set in location \"%V\"", &variable[i].variable->name, variable[i].name, &core_loc_conf->name);
                    return NGX_ERROR;
                }
                continue;
            }
        }
        if (variable[i].row >= PQntuples(pd->res) || variable[i].col >= PQnfields(pd->res)) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value out of range of the received result-set (rows:%d cols:%d) in location \"%V\"", &variable[i].variable->name, PQntuples(pd->res), PQnfields(pd->res), &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
        if (PQgetisnull(pd->res, variable[i].row, variable[i].col)) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-NULL value in location \"%V\"", &variable[i].variable->name, &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
        if (!(elts[i].len = PQgetlength(pd->res, variable[i].row, variable[i].col))) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-zero length value in location \"%V\"", &variable[i].variable->name, &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
        if (!(elts[i].data = ngx_pnalloc(r->pool, elts[i].len))) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc");
            return NGX_ERROR;
        }
        ngx_memcpy(elts[i].data, PQgetvalue(pd->res, variable[i].row, variable[i].col), elts[i].len);
    }
    return NGX_OK;
}


static ngx_http_variable_t ngx_postgres_module_variables[] = {
  { .name = ngx_string("postgres_nfields"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_nfields,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
  { .name = ngx_string("postgres_ntuples"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_ntuples,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
  { .name = ngx_string("postgres_cmdtuples"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_cmdtuples,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
  { .name = ngx_string("postgres_query"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_query,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
    ngx_http_null_variable
};


ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_postgres_module_variables; v->name.len; v++) {
        ngx_http_variable_t *variable = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!variable) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_http_add_variable"); return NGX_ERROR; }
        variable->get_handler = v->get_handler;
        variable->data = v->data;
    }
    return NGX_OK;
}


ngx_conf_enum_t ngx_postgres_requirement_options[] = {
    { ngx_string("optional"), 0 },
    { ngx_string("required"), 1 },
    { ngx_null_string, 0 }
};


char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len < 2) return "empty variable name";
    if (elts[1].data[0] != '$') return "invalid variable name";
    elts[1].len--;
    elts[1].data++;
    if (!elts[3].len) return "empty col";
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->variables == NGX_CONF_UNSET_PTR && !(location_conf->variables = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_variable_t)))) return "!ngx_array_create";
    ngx_postgres_variable_t *variable = ngx_array_push(location_conf->variables);
    if (!variable) return "!ngx_array_push";
    if (!(variable->variable = ngx_http_add_variable(cf, &elts[1], NGX_HTTP_VAR_CHANGEABLE))) return "!ngx_http_add_variable";
    if (ngx_http_get_variable_index(cf, &elts[1]) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    if (!variable->variable->get_handler) {
        variable->variable->get_handler = ngx_postgres_variable_get;
        variable->variable->data = (uintptr_t) location_conf->variables->nelts - 1;
    }
    if ((variable->row = ngx_atoi(elts[2].data, elts[2].len)) == NGX_ERROR) return "invalid row number";
    if ((variable->col = ngx_atoi(elts[3].data, elts[3].len)) == NGX_ERROR) { /* get col by name */
        if (!(variable->name = ngx_pnalloc(cf->pool, elts[3].len + 1))) return "!ngx_pnalloc";
        (void) ngx_cpystrn(variable->name, elts[3].data, elts[3].len + 1);
    }
    if (cf->args->nelts == 4) variable->required = 0; else { /* user-specified value */
        ngx_conf_enum_t *e = ngx_postgres_requirement_options;
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[4].len && !ngx_strncasecmp(e[i].name.data, elts[4].data, elts[4].len)) { variable->required = e[i].value; break; }
        if (!e[i].name.len) return "invalid requirement option";
    }
    return NGX_CONF_OK;
}
