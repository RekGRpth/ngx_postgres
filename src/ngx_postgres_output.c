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

#include <math.h>
#include <postgresql/server/catalog/pg_type_d.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_upstream.h"


ngx_int_t ngx_postgres_output_value(ngx_http_request_t *r) {
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (context->ntuples != 1 || context->nfields != 1) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: \"postgres_output value\" received %d value(s) instead of expected single value in location \"%V\"", context->ntuples * context->nfields, &core_loc_conf->name);
        context->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    if (PQgetisnull(context->res, 0, 0)) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: \"postgres_output value\" received NULL value in location \"%V\"", &core_loc_conf->name);
        context->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    size_t size = PQgetlength(context->res, 0, 0);
    if (!size) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: \"postgres_output value\" received empty value in location \"%V\"", &core_loc_conf->name);
        context->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    b->last = ngx_copy(b->last, PQgetvalue(context->res, 0, 0), size);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->next = NULL;
    context->response = chain; /* set output response */
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_output_text_csv(ngx_http_request_t *r) {
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    size_t size = 0; /* pre-calculate total length up-front for single buffer allocation */
    for (ngx_int_t row = 0; row < context->ntuples; row++) for (ngx_int_t col = 0; col < context->nfields; col++) if (PQgetisnull(context->res, row, col)) size += sizeof("(null)") - 1; else size += PQgetlength(context->res, row, col); /* field string data */
    size += context->ntuples * context->nfields - 1; /* delimiters */
    if (!context->ntuples || !size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    /* fill data */
    for (ngx_int_t row = 0; row < context->ntuples; row++) {
        for (ngx_int_t col = 0; col < context->nfields; col++) {
            if (PQgetisnull(context->res, row, col)) b->last = ngx_copy(b->last, "(null)", sizeof("(null)") - 1);
            else if ((size = PQgetlength(context->res, row, col))) b->last = ngx_copy(b->last, PQgetvalue(context->res, row, col), size);
            if (row != context->ntuples - 1 && col != context->nfields - 1) b->last = ngx_copy(b->last, "\t", 1);
        }
        if (row != context->ntuples - 1) b->last = ngx_copy(b->last, "\n", 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->next = NULL;
    context->response = chain; /* set output response */
    return NGX_DONE;
}


ngx_int_t ngx_postgres_output_text(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


ngx_int_t ngx_postgres_output_csv(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


ngx_int_t ngx_postgres_output_chain(ngx_http_request_t *r) {
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (!r->header_sent) {
        ngx_http_clear_content_length(r);
        ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        r->headers_out.status = context->status ? ngx_abs(context->status) : NGX_HTTP_OK;
        if (location_conf->output.handler == &ngx_postgres_output_json) {
            ngx_str_set(&r->headers_out.content_type, "application/json");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (location_conf->output.handler == &ngx_postgres_output_text) {
            ngx_str_set(&r->headers_out.content_type, "text/plain");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (location_conf->output.handler == &ngx_postgres_output_csv) {
            ngx_str_set(&r->headers_out.content_type, "text/csv");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (location_conf->output.handler) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            r->headers_out.content_type = core_loc_conf->default_type;
            r->headers_out.content_type_len = core_loc_conf->default_type.len;
        }
        r->headers_out.content_type_lowcase = NULL;
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    if (!context->response) return NGX_DONE;
    ngx_int_t rc = ngx_http_output_filter(r, context->response);
    if (rc == NGX_ERROR || rc > NGX_OK) return rc;
    ngx_chain_update_chains(r->pool, &r->upstream->free_bufs, &r->upstream->busy_bufs, &context->response, r->upstream->output.tag);
    return rc;
}


ngx_int_t ngx_postgres_output_json(ngx_http_request_t *r) {
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    size_t size = 0;
    if (context->ntuples == 1 && context->nfields == 1 && (PQftype(context->res, 0) == JSONOID || PQftype(context->res, 0) == JSONBOID)) size = PQgetlength(context->res, 0, 0); else {
        if (context->ntuples > 1) size += 2; // [] + \0
        for (ngx_int_t row = 0; row < context->ntuples; row++) {
            size += sizeof("{}") - 1;
            for (ngx_int_t col = 0; col < context->nfields; col++) {
                if (PQgetisnull(context->res, row, col)) size += sizeof("null") - 1; else {
                    int col_length = PQgetlength(context->res, row, col);
                    if ((PQftype(context->res, col) < INT8OID || PQftype(context->res, col) > INT4OID) && (PQftype(context->res, col) != JSONBOID && PQftype(context->res, col) != JSONOID)) { //not numbers or json
                        if (PQftype(context->res, col) == BOOLOID) switch (PQgetvalue(context->res, row, col)[0]) {
                            case 't': case 'T': col_length = sizeof("true") - 1; break;
                            case 'f': case 'F': col_length = sizeof("false") - 1; break;
                        } else {
                            size += sizeof("\"\"") - 1;
                            col_length += ngx_escape_json(NULL, (u_char *)PQgetvalue(context->res, row, col), col_length);
                        }
                    }
                    size += col_length; /* field string data */
                }
            }
        }
        for (ngx_int_t col = 0; col < context->nfields; col++) size += (ngx_strlen(PQfname(context->res, col)) + 3) * context->ntuples; // extra "":
        size += context->ntuples * (context->nfields - 1); /* column delimeters */
        size += context->ntuples - 1;                      /* row delimeters */
    }
    if (!context->ntuples || !size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    if (context->ntuples == 1 && context->nfields == 1 && (PQftype(context->res, 0) == JSONOID || PQftype(context->res, 0) == JSONBOID)) b->last = ngx_copy(b->last, PQgetvalue(context->res, 0, 0), PQgetlength(context->res, 0, 0)); else { /* fill data */
        if (context->ntuples > 1) b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (ngx_int_t row = 0; row < context->ntuples; row++) {
            if (row > 0) b->last = ngx_copy(b->last, ",", 1);
            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (ngx_int_t col = 0; col < context->nfields; col++) {
                if (col > 0) b->last = ngx_copy(b->last, ",", 1);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = ngx_copy(b->last, PQfname(context->res, col), ngx_strlen(PQfname(context->res, col)));
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);
                if (PQgetisnull(context->res, row, col)) b->last = ngx_copy(b->last, "null", sizeof("null") - 1); else {
                    if (((PQftype(context->res, col) < INT8OID || PQftype(context->res, col) > INT4OID) && (PQftype(context->res, col) != JSONBOID && PQftype(context->res, col) != JSONOID)) || !PQgetlength(context->res, row, col)) { //not numbers or json
                        if (PQftype(context->res, col) == BOOLOID) switch (PQgetvalue(context->res, row, col)[0]) {
                            case 't': case 'T': b->last = ngx_copy(b->last, "true", sizeof("true") - 1); break;
                            case 'f': case 'F': b->last = ngx_copy(b->last, "false", sizeof("false") - 1); break;
                        } else {
                            b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                            if (PQgetlength(context->res, row, col) > 0) b->last = (u_char *) ngx_escape_json(b->last, (u_char *)PQgetvalue(context->res, row, col), PQgetlength(context->res, row, col));
                            b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                        }
                    } else b->last = ngx_copy(b->last, PQgetvalue(context->res, row, col), PQgetlength(context->res, row, col));
                }
            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        if (context->ntuples > 1) b->last = ngx_copy(b->last, "]", sizeof("]") - 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    chain->next = NULL;
    context->response = chain; /* set output response */
    return NGX_DONE;
}
