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
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (PQntuples(pd->res) != 1 || PQnfields(pd->res) != 1) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received %d value(s) instead of expected single value in location \"%V\"", PQntuples(pd->res) * PQnfields(pd->res), &core_loc_conf->name);
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    if (PQgetisnull(pd->res, 0, 0)) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received NULL value in location \"%V\"", &core_loc_conf->name);
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    size_t size = PQgetlength(pd->res, 0, 0);
    if (!size) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received empty value in location \"%V\"", &core_loc_conf->name);
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    b->last = ngx_copy(b->last, PQgetvalue(pd->res, 0, 0), size);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->response = chain; /* set output response */
    return NGX_DONE;
}


static size_t ngx_postgres_count(u_char *s, size_t l, u_char c) {
    size_t d;
    for (d = 0; l-- > 0; d++, s++) if (*s == c) d++;
    return d;
}


static u_char *ngx_postgres_escape(u_char *d, u_char *s, size_t l, u_char c) {
    for (; l-- > 0; *d++ = *s++) if (*s == c) *d++ = c;
    return d;
}


static ngx_int_t ngx_postgres_output_text_csv(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (!PQntuples(pd->res) || !PQnfields(pd->res)) return NGX_DONE;
    size_t size = 0;
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location_conf->output.header) {
        size += PQnfields(pd->res) - 1; // header delimiters
        size++; // header new line
        for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
            if (location_conf->output.quote) size++;
            if (location_conf->output.escape) size += ngx_postgres_count((u_char *)PQfname(pd->res, col), ngx_strlen(PQfname(pd->res, col)), location_conf->output.escape);
            else size += ngx_strlen(PQfname(pd->res, col));
            if (location_conf->output.quote) size++;
        }
    }
    size += PQntuples(pd->res) * (PQnfields(pd->res) - 1); // value delimiters
    size += PQntuples(pd->res) - 1; // value new line
    for (ngx_int_t row = 0; row < PQntuples(pd->res); row++) for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
        if (PQgetisnull(pd->res, row, col)) size += location_conf->output.null.len; else switch (PQftype(pd->res, col)) {
            case BITOID:
            case BOOLOID:
            case CIDOID:
            case FLOAT4OID:
            case FLOAT8OID:
            case INT2OID:
            case INT4OID:
            case INT8OID:
            case NUMERICOID:
            case OIDOID:
            case TIDOID:
            case XIDOID: if (location_conf->output.string) {
                size += PQgetlength(pd->res, row, col);
                break;
            } // fall through
            default: {
                if (location_conf->output.quote) size++;
                if (PQgetlength(pd->res, row, col)) {
                    if (location_conf->output.escape) size += ngx_postgres_count((u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col), location_conf->output.escape);
                    else size += PQgetlength(pd->res, row, col);
                }
                if (location_conf->output.quote) size++;
            } break;
        }
    }
    if (!size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    if (location_conf->output.header) {
        for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
            if (col > 0) *b->last++ = location_conf->output.delimiter;
            if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
            if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQfname(pd->res, col), ngx_strlen(PQfname(pd->res, col)), location_conf->output.escape);
            else b->last = ngx_copy(b->last, PQfname(pd->res, col), ngx_strlen(PQfname(pd->res, col)));
            if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
        }
        *b->last++ = '\n';
    }
    for (ngx_int_t row = 0; row < PQntuples(pd->res); row++) {
        if (row > 0) *b->last++ = '\n';
        for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
            if (col > 0) *b->last++ = location_conf->output.delimiter;
            if (PQgetisnull(pd->res, row, col)) b->last = ngx_copy(b->last, location_conf->output.null.data, location_conf->output.null.len); else switch (PQftype(pd->res, col)) {
                case BITOID:
                case BOOLOID:
                case CIDOID:
                case FLOAT4OID:
                case FLOAT8OID:
                case INT2OID:
                case INT4OID:
                case INT8OID:
                case NUMERICOID:
                case OIDOID:
                case TIDOID:
                case XIDOID: if (location_conf->output.string) {
                    if (PQgetlength(pd->res, row, col)) b->last = ngx_copy(b->last, (u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col));
                    break;
                } // fall through
                default: {
                    if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
                    if (PQgetlength(pd->res, row, col)) {
                        if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col), location_conf->output.escape);
                        else b->last = ngx_copy(b->last, (u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col));
                    }
                    if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
                } break;
            }
        }
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->response = chain; /* set output response */
    return NGX_DONE;
}


ngx_int_t ngx_postgres_output_text(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


ngx_int_t ngx_postgres_output_csv(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


ngx_int_t ngx_postgres_output_chain(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (!r->header_sent) {
        ngx_http_clear_content_length(r);
        ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        r->headers_out.status = pd->status ? ngx_abs(pd->status) : NGX_HTTP_OK;
        ngx_postgres_data_t *pd = r->upstream->peer.data;
        if (pd->common.charset.len) r->headers_out.charset = pd->common.charset;
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
        if (pd->response) r->headers_out.content_length_n = pd->response->buf->end - pd->response->buf->start;
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    }
    if (!pd->response) return NGX_DONE;
    ngx_int_t rc = ngx_http_output_filter(r, pd->response);
    if (rc == NGX_ERROR || rc > NGX_OK) return rc;
    ngx_chain_update_chains(r->pool, &r->upstream->free_bufs, &r->upstream->busy_bufs, &pd->response, r->upstream->output.tag);
    return rc;
}


ngx_int_t ngx_postgres_output_json(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    size_t size = 0;
    if (PQntuples(pd->res) == 1 && PQnfields(pd->res) == 1 && (PQftype(pd->res, 0) == JSONOID || PQftype(pd->res, 0) == JSONBOID)) size = PQgetlength(pd->res, 0, 0); else {
        if (PQntuples(pd->res) > 1) size += 2; // [] + \0
        for (ngx_int_t row = 0; row < PQntuples(pd->res); row++) {
            size += sizeof("{}") - 1;
            for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
                if (PQgetisnull(pd->res, row, col)) size += sizeof("null") - 1; else switch (PQftype(pd->res, col)) {
                    case BITOID:
                    case CIDOID:
                    case FLOAT4OID:
                    case FLOAT8OID:
                    case INT2OID:
                    case INT4OID:
                    case INT8OID:
                    case JSONBOID:
                    case JSONOID:
                    case NUMERICOID:
                    case OIDOID:
                    case TIDOID:
                    case XIDOID: size += PQgetlength(pd->res, row, col); break;
                    case BOOLOID: switch (PQgetvalue(pd->res, row, col)[0]) {
                        case 't': case 'T': size += sizeof("true") - 1; break;
                        case 'f': case 'F': size += sizeof("false") - 1; break;
                    } break;
                    default: size += sizeof("\"\"") - 1 + PQgetlength(pd->res, row, col) + ngx_escape_json(NULL, (u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col)); break;
                }
            }
        }
        for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) size += (ngx_strlen(PQfname(pd->res, col)) + 3) * PQntuples(pd->res); // extra "":
        size += PQntuples(pd->res) * (PQnfields(pd->res) - 1); /* column delimiters */
        size += PQntuples(pd->res) - 1;                      /* row delimiters */
    }
    if (!PQntuples(pd->res) || !size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    if (PQntuples(pd->res) == 1 && PQnfields(pd->res) == 1 && (PQftype(pd->res, 0) == JSONOID || PQftype(pd->res, 0) == JSONBOID)) b->last = ngx_copy(b->last, PQgetvalue(pd->res, 0, 0), PQgetlength(pd->res, 0, 0)); else { /* fill data */
        if (PQntuples(pd->res) > 1) b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (ngx_int_t row = 0; row < PQntuples(pd->res); row++) {
            if (row > 0) b->last = ngx_copy(b->last, ",", 1);
            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (ngx_int_t col = 0; col < PQnfields(pd->res); col++) {
                if (col > 0) b->last = ngx_copy(b->last, ",", 1);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = ngx_copy(b->last, PQfname(pd->res, col), ngx_strlen(PQfname(pd->res, col)));
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);
                if (PQgetisnull(pd->res, row, col)) b->last = ngx_copy(b->last, "null", sizeof("null") - 1); else switch (PQftype(pd->res, col)) {
                    case BITOID:
                    case CIDOID:
                    case FLOAT4OID:
                    case FLOAT8OID:
                    case INT2OID:
                    case INT4OID:
                    case INT8OID:
                    case JSONBOID:
                    case JSONOID:
                    case NUMERICOID:
                    case OIDOID:
                    case TIDOID:
                    case XIDOID: b->last = ngx_copy(b->last, PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col)); break;
                    case BOOLOID: switch (PQgetvalue(pd->res, row, col)[0]) {
                        case 't': case 'T': b->last = ngx_copy(b->last, "true", sizeof("true") - 1); break;
                        case 'f': case 'F': b->last = ngx_copy(b->last, "false", sizeof("false") - 1); break;
                    } break;
                    default: {
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                        if (PQgetlength(pd->res, row, col) > 0) b->last = (u_char *) ngx_escape_json(b->last, (u_char *)PQgetvalue(pd->res, row, col), PQgetlength(pd->res, row, col));
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                    } break;
                }
            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        if (PQntuples(pd->res) > 1) b->last = ngx_copy(b->last, "]", sizeof("]") - 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->response = chain; /* set output response */
    return NGX_DONE;
}
