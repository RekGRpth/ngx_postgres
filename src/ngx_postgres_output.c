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
#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ngx_postgres_ddebug.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include <math.h>


ngx_int_t
ngx_postgres_output_value(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_ctx_t        *pgctx;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_chain_t               *cl;
    ngx_buf_t                 *b;
    size_t                     size;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    if ((pgctx->var_rows != 1) || (pgctx->var_cols != 1)) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received %d value(s)"
                      " instead of expected single value in location \"%V\"",
                      pgctx->var_rows * pgctx->var_cols, &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    if (PQgetisnull(res, 0, 0)) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received NULL value"
                      " in location \"%V\"", &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    size = PQgetlength(res, 0, 0);
    if (size == 0) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received empty value"
                      " in location \"%V\"", &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    b->last = ngx_copy(b->last, PQgetvalue(res, 0, 0), size);

    if (b->last != b->end) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->next = NULL;

    /* set output response */
    pgctx->response = cl;

    dd("returning NGX_DONE");
    return NGX_DONE;
}


int hex2bin( const char *s )
{
    int ret=0;
    int i;
    for( i=0; i<2; i++ )
    {
        char c = *s++;
        int n=0;
        if( '0'<=c && c<='9' )
            n = c-'0';
        else if( 'a'<=c && c<='f' )
            n = 10 + c-'a';
        else if( 'A'<=c && c<='F' )
            n = 10 + c-'A';
        ret = n + ret*16;
    }
    return ret;
}

ngx_int_t
ngx_postgres_output_hex(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_ctx_t        *pgctx;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_chain_t               *cl;
    ngx_buf_t                 *b;
    size_t                     size;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    if ((pgctx->var_rows != 1) || (pgctx->var_cols != 1)) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received %d value(s)"
                      " instead of expected single value in location \"%V\"",
                      pgctx->var_rows * pgctx->var_cols, &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    if (PQgetisnull(res, 0, 0)) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received NULL value"
                      " in location \"%V\"", &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    size = PQgetlength(res, 0, 0);
    if (size == 0) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "postgres: \"postgres_output value\" received empty value"
                      " in location \"%V\"", &clcf->name);

        dd("returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR");
        pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, floor(size / 2));
    if (b == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    char *value = PQgetvalue(res, 0, 0);

    unsigned int start = 0;
    if (value[start] == '\\')
        start++;
    if (value[start] == 'x')
        start++;

    for (; start < size; start += 2)
        *(b->last++) = hex2bin(value + start);
    //if (b->last != b->end) {
    //    dd("returning NGX_ERROR");
    //    return NGX_ERROR;
    //}

    cl->next = NULL;

    /* set output response */
    pgctx->response = cl;

    dd("returning NGX_DONE");
    return NGX_DONE;
}
ngx_int_t
ngx_postgres_output_text(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_ctx_t        *pgctx;
    ngx_chain_t               *cl;
    ngx_buf_t                 *b;
    size_t                     size;
    ngx_int_t                  col_count, row_count, col, row;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    col_count = pgctx->var_cols;
    row_count = pgctx->var_rows;

    /* pre-calculate total length up-front for single buffer allocation */
    size = 0;

    for (row = 0; row < row_count; row++) {
        for (col = 0; col < col_count; col++) {
            if (PQgetisnull(res, row, col)) {
                size += sizeof("(null)") - 1;
            } else {
                size += PQgetlength(res, row, col);  /* field string data */
            }
        }
    }

    size += row_count * col_count - 1;               /* delimiters */

    if ((row_count == 0) || (size == 0)) {
        dd("returning NGX_DONE (empty result)");
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    /* fill data */
    for (row = 0; row < row_count; row++) {
        for (col = 0; col < col_count; col++) {
            if (PQgetisnull(res, row, col)) {
                b->last = ngx_copy(b->last, "(null)", sizeof("(null)") - 1);
            } else {
                size = PQgetlength(res, row, col);
                if (size) {
                    b->last = ngx_copy(b->last, PQgetvalue(res, row, col),
                                       size);
                }
            }

            if ((row != row_count - 1) || (col != col_count - 1)) {
                b->last = ngx_copy(b->last, "\n", 1);
            }
        }
    }

    if (b->last != b->end) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->next = NULL;

    /* set output response */
    pgctx->response = cl;

    dd("returning NGX_DONE");
    return NGX_DONE;
}

ngx_int_t
ngx_postgres_output_rds(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_ctx_t  *pgctx;
    ngx_chain_t         *first, *last;
    ngx_int_t            col_count, row_count, aff_count, row;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    col_count = pgctx->var_cols;
    row_count = pgctx->var_rows;
    aff_count = (pgctx->var_affected == NGX_ERROR) ? 0 : pgctx->var_affected;

    /* render header */
    first = last = ngx_postgres_render_rds_header(r, r->pool, res, col_count,
                                                  aff_count);
    if (last == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        goto done;
    }

    /* render columns */
    last->next = ngx_postgres_render_rds_columns(r, r->pool, res, col_count);
    if (last->next == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }
    last = last->next;

    /* render rows */
    for (row = 0; row < row_count; row++) {
        last->next = ngx_postgres_render_rds_row(r, r->pool, res, col_count,
                                                 row, (row == row_count - 1));
        if (last->next == NULL) {
            dd("returning NGX_ERROR");
            return NGX_ERROR;
        }
        last = last->next;
    }

    /* render row terminator (for empty result-set only) */
    if (row == 0) {
        last->next = ngx_postgres_render_rds_row_terminator(r, r->pool);
        if (last->next == NULL) {
            dd("returning NGX_ERROR");
            return NGX_ERROR;
        }
        last = last->next;
    }

done:

    last->next = NULL;

    /* set output response */
    pgctx->response = first;

    dd("returning NGX_DONE");
    return NGX_DONE;
}

ngx_chain_t *
ngx_postgres_render_rds_header(ngx_http_request_t *r, ngx_pool_t *pool,
    PGresult *res, ngx_int_t col_count, ngx_int_t aff_count)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    size_t        size;
    char         *errstr;
    size_t        errstr_len;

    dd("entering");

    errstr = PQresultErrorMessage(res);
    errstr_len = ngx_strlen(errstr);

    size = sizeof(uint8_t)        /* endian type */
         + sizeof(uint32_t)       /* format version */
         + sizeof(uint8_t)        /* result type */
         + sizeof(uint16_t)       /* standard error code */
         + sizeof(uint16_t)       /* driver-specific error code */
         + sizeof(uint16_t)       /* driver-specific error string length */
         + (uint16_t) errstr_len  /* driver-specific error string data */
         + sizeof(uint64_t)       /* rows affected */
         + sizeof(uint64_t)       /* insert id */
         + sizeof(uint16_t)       /* column count */
         ;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    /* fill data */
#if NGX_HAVE_LITTLE_ENDIAN
    *b->last++ = 0;
#else
    *b->last++ = 1;
#endif

    *(uint32_t *) b->last = (uint32_t) resty_dbd_stream_version;
    b->last += sizeof(uint32_t);

    *b->last++ = 0;

    *(uint16_t *) b->last = (uint16_t) 0;
    b->last += sizeof(uint16_t);

    *(uint16_t *) b->last = (uint16_t) PQresultStatus(res);
    b->last += sizeof(uint16_t);

    *(uint16_t *) b->last = (uint16_t) errstr_len;
    b->last += sizeof(uint16_t);

    if (errstr_len) {
        b->last = ngx_copy(b->last, (u_char *) errstr, errstr_len);
    }

    *(uint64_t *) b->last = (uint64_t) aff_count;
    b->last += sizeof(uint64_t);

    *(uint64_t *) b->last = (uint64_t) PQoidValue(res);
    b->last += sizeof(uint64_t);

    *(uint16_t *) b->last = (uint16_t) col_count;
    b->last += sizeof(uint16_t);

    if (b->last != b->end) {
        dd("returning NULL");
        return NULL;
    }

    dd("returning");
    return cl;
}

ngx_chain_t *
ngx_postgres_render_rds_columns(ngx_http_request_t *r, ngx_pool_t *pool,
    PGresult *res, ngx_int_t col_count)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    size_t        size;
    ngx_int_t     col;
    Oid           col_type;
    char         *col_name;
    size_t        col_name_len;

    dd("entering");

    /* pre-calculate total length up-front for single buffer allocation */
    size = col_count
         * (sizeof(uint16_t)    /* standard column type */
            + sizeof(uint16_t)  /* driver-specific column type */
            + sizeof(uint16_t)  /* column name string length */
           )
         ;

    for (col = 0; col < col_count; col++) {
        size += ngx_strlen(PQfname(res, col));  /* column name string data */
    }

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    /* fill data */
    for (col = 0; col < col_count; col++) {
        col_type = PQftype(res, col);
        col_name = PQfname(res, col);
        col_name_len = (uint16_t) ngx_strlen(col_name);

        *(uint16_t *) b->last = (uint16_t) ngx_postgres_rds_col_type(col_type);
        b->last += sizeof(uint16_t);

        *(uint16_t *) b->last = col_type;
        b->last += sizeof(uint16_t);

        *(uint16_t *) b->last = col_name_len;
        b->last += sizeof(uint16_t);

        b->last = ngx_copy(b->last, col_name, col_name_len);
    }

    if (b->last != b->end) {
        dd("returning NULL");
        return NULL;
    }

    dd("returning");
    return cl;
}

ngx_chain_t *
ngx_postgres_render_rds_row(ngx_http_request_t *r, ngx_pool_t *pool,
    PGresult *res, ngx_int_t col_count, ngx_int_t row, ngx_int_t last_row)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    size_t        size;
    ngx_int_t     col;

    dd("entering, row:%d", (int) row);

    /* pre-calculate total length up-front for single buffer allocation */
    size = sizeof(uint8_t)                 /* row number */
         + (col_count * sizeof(uint32_t))  /* field string length */
         ;

    if (last_row) {
        size += sizeof(uint8_t);
    }

    for (col = 0; col < col_count; col++) {
        size += PQgetlength(res, row, col);  /* field string data */
    }

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    /* fill data */
    *b->last++ = (uint8_t) 1; /* valid row */

    for (col = 0; col < col_count; col++) {
        if (PQgetisnull(res, row, col)) {
            *(uint32_t *) b->last = (uint32_t) -1;
             b->last += sizeof(uint32_t);
        } else {
            size = PQgetlength(res, row, col);
            *(uint32_t *) b->last = (uint32_t) size;
            b->last += sizeof(uint32_t);

            if (size) {
                b->last = ngx_copy(b->last, PQgetvalue(res, row, col), size);
            }
        }
    }

    if (last_row) {
        *b->last++ = (uint8_t) 0; /* row terminator */
    }

    if (b->last != b->end) {
        dd("returning NULL");
        return NULL;
    }

    dd("returning");
    return cl;
}

ngx_chain_t *
ngx_postgres_render_rds_row_terminator(ngx_http_request_t *r, ngx_pool_t *pool)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    dd("entering");

    b = ngx_create_temp_buf(pool, sizeof(uint8_t));
    if (b == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        dd("returning NULL");
        return NULL;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;

    /* fill data */
    *b->last++ = (uint8_t) 0; /* row terminator */

    if (b->last != b->end) {
        dd("returning NULL");
        return NULL;
    }

    dd("returning");
    return cl;
}

ngx_int_t
ngx_postgres_output_chain(ngx_http_request_t *r, ngx_chain_t *cl)
{
    ngx_http_upstream_t       *u = r->upstream;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_postgres_loc_conf_t   *pglcf;
    ngx_postgres_ctx_t        *pgctx;
    ngx_int_t                  rc;

    dd("entering");

    if (!r->header_sent) {
        ngx_http_clear_content_length(r);

        pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

        r->headers_out.status = pgctx->status ? ngx_abs(pgctx->status)
                                              : NGX_HTTP_OK;


        if (pglcf->output_handler == &ngx_postgres_output_rds) {
            /* RDS for output rds */
            r->headers_out.content_type.data = (u_char *) rds_content_type;
            r->headers_out.content_type.len = rds_content_type_len;
            r->headers_out.content_type_len = rds_content_type_len;
        //} else if (pglcf->output_handler == &ngx_postgres_output_json) {
        //    This thing crashes nginx for some reason...
        //    r->headers_out.content_type.data = (u_char *) json_content_type;
        //    r->headers_out.content_type.len = json_content_type_len;
        //    r->headers_out.content_type_len = json_content_type_len;
        } else if (pglcf->output_handler != NULL) {
            /* default type for output value|row */
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            r->headers_out.content_type = clcf->default_type;
            r->headers_out.content_type_len = clcf->default_type.len;
        }

        r->headers_out.content_type_lowcase = NULL;

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            dd("returning rc:%d", (int) rc);
            return rc;
        }
    }

    if (cl == NULL) {
        dd("returning NGX_DONE");
        return NGX_DONE;
    }

    rc = ngx_http_output_filter(r, cl);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        dd("returning rc:%d", (int) rc);
        return rc;
    }

#if defined(nginx_version) && (nginx_version >= 1001004)
    ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs, &cl,
                            u->output.tag);
#else
    ngx_chain_update_chains(&u->free_bufs, &u->busy_bufs, &cl, u->output.tag);
#endif

    dd("returning rc:%d", (int) rc);
    return rc;
}

rds_col_type_t
ngx_postgres_rds_col_type(Oid col_type)
{
    switch (col_type) {
    case 20: /* int8 */
        return rds_col_type_bigint;
    case 1560: /* bit */
        return rds_col_type_bit;
    case 1562: /* varbit */
        return rds_col_type_bit_varying;
    case 16: /* bool */
        return rds_col_type_bool;
    case 18: /* char */
        return rds_col_type_char;
    case 19: /* name */
        /* FALLTROUGH */
    case 25: /* text */
        /* FALLTROUGH */
    case 1043: /* varchar */
        return rds_col_type_varchar;
    case 1082: /* date */
        return rds_col_type_date;
    case 701: /* float8 */
        return rds_col_type_double;
    case 23: /* int4 */
        return rds_col_type_integer;
    case 1186: /* interval */
        return rds_col_type_interval;
    case 1700: /* numeric */
        return rds_col_type_decimal;
    case 700: /* float4 */
        return rds_col_type_real;
    case 21: /* int2 */
        return rds_col_type_smallint;
    case 1266: /* timetz */
        return rds_col_type_time_with_time_zone;
    case 1083: /* time */
        return rds_col_type_time;
    case 1184: /* timestamptz */
        return rds_col_type_timestamp_with_time_zone;
    case 1114: /* timestamp */
        return rds_col_type_timestamp;
    case 142: /* xml */
        return rds_col_type_xml;
    case 17: /* bytea */
        return rds_col_type_blob;
    default:
        return rds_col_type_unknown;
    }
}



ngx_int_t
ngx_postgres_output_json(ngx_http_request_t *r, PGresult *res)
{
    ngx_postgres_ctx_t        *pgctx;
    ngx_chain_t               *cl;
    ngx_buf_t                 *b;
    size_t                     size;
    ngx_int_t                  col_count, row_count, col, row;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    col_count = pgctx->var_cols;
    row_count = pgctx->var_rows;

    int col_type = 0;

    // single row with single json column, return that column
    if (row_count == 1 && col_count == 1 && (PQftype(res, 0) == 114 || PQftype(res, 0) == 3802)) {
        size = PQgetlength(res, 0, 0) + 1;
    } else {
        /* pre-calculate total length up-front for single buffer allocation */
        size = 2 + 1; // [] + \0


        for (row = 0; row < row_count; row++) {
            size += sizeof("{}") - 1;
            for (col = 0; col < col_count; col++) {
                if (PQgetisnull(res, row, col)) {
                    size += sizeof("null") - 1;
                } else {
                    col_type = PQftype(res, col);
                    int col_length = PQgetlength(res, row, col);

                    if ((col_type < 20 || col_type > 23) && (col_type != 3802 && col_type != 114)) { //not numbers or json
                        size += sizeof("\"\"") - 1;

                        char *col_value = PQgetvalue(res, row, col);
                        col_length += ngx_escape_json(NULL, (u_char *) col_value, col_length);

                    }

                    size += col_length;  /* field string data */
                }
            }
        }
        for (col = 0; col < col_count; col++) {
            char *col_name = PQfname(res, col);
            size += (strlen(col_name) + 3) * row_count; // extra "":
        }

        size += row_count * (col_count - 1);               /* column delimeters */
        size += row_count - 1;                            /* row delimeters */

    }

    if ((row_count == 0) || (size == 0)) {
        dd("returning NGX_DONE (empty result)");
        return NGX_DONE;
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;


    if (row_count == 1 && col_count == 1 && (PQftype(res, 0) == 114 || PQftype(res, 0) == 3802)) {

        b->last = ngx_copy(b->last, PQgetvalue(res, 0, 0),
                           size - 1);
        b->last = ngx_copy(b->last, "", sizeof(""));
    } else {
        // YF: Populate empty parent req variables with names of columns, if in subrequest
        // HACK, LOL! Better move me out
        if (r != r->main) {

            ngx_str_t export_variable;
            for (col = 0; col < col_count; col++) {
                char *col_name = PQfname(res, col);
                export_variable.data = (unsigned char*)col_name;
                export_variable.len = strlen(col_name);

                ngx_uint_t meta_variable_hash = ngx_hash_key(export_variable.data, export_variable.len);
                ngx_http_variable_value_t *raw_meta = ngx_http_get_variable( r->main, &export_variable, meta_variable_hash  );
                if (!raw_meta->not_found && raw_meta->len == 0) {
                    raw_meta->valid = 1;
                    int exported_length = PQgetlength(res, 0, col);
                    char *exported_value = ngx_palloc(r->main->pool, exported_length);
                    ngx_memcpy(exported_value, PQgetvalue(res, 0, col), exported_length);
                    raw_meta->len = exported_length;
                    raw_meta->data = (unsigned char*)exported_value;
                }
            }
        }

        /* fill data */
        b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (row = 0; row < row_count; row++) {
            if (row > 0)
                b->last = ngx_copy(b->last, ",", 1);

            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (col = 0; col < col_count; col++) {
                if (col > 0)
                    b->last = ngx_copy(b->last, ",", 1);

                char *col_name = PQfname(res, col);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = ngx_copy(b->last, col_name, strlen(col_name));
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);

                if (PQgetisnull(res, row, col)) {
                    b->last = ngx_copy(b->last, "null", sizeof("null") - 1);
                } else {
                    size = PQgetlength(res, row, col);

                    col_type = PQftype(res, col);
                    //not numbers or json
                    if (((col_type < 20 || col_type > 23) && (col_type != 3802 && col_type != 114)) || size == 0) {
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);

                        if (size > 0)
                            b->last = (u_char *) ngx_escape_json(b->last, (u_char *) PQgetvalue(res, row, col), size);


                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                    } else {
                        b->last = ngx_copy(b->last, PQgetvalue(res, row, col),
                                           size);
                    }
                }

            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        b->last = ngx_copy(b->last, "]", sizeof("]"));
    }

    //fprintf(stdout, "PRINTING %d\n", b->end - b->last);
    //fprintf(stdout, "PRINTING %s\n", b->pos);
    if (b->last != b->end) {
        dd("returning NGX_ERROR");
        return NGX_ERROR;
    }

    cl->next = NULL;

    /* set output response */
    pgctx->response = cl;

    dd("returning NGX_DONE");
    return NGX_DONE;
}
