#include <catalog/pg_type_d.h>
#include "ngx_postgres_include.h"


static ngx_buf_t *ngx_postgres_buffer(ngx_http_request_t *r, size_t size) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_chain_t *cl, **ll;
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) ll = &cl->next;
    if (!(cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_chain_get_free_buf"); return NULL; }
    *ll = cl;
    cl->buf->flush = 1;
    cl->buf->memory = 1;
    ngx_buf_t *b = cl->buf;
    if (b->start) ngx_pfree(r->pool, b->start);
    if (!(b->start = ngx_palloc(r->pool, size))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_palloc"); return NULL; }
    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;
    b->tag = u->output.tag;
    return b;
}


ngx_int_t ngx_postgres_output_value(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    r->headers_out.content_type = core->default_type;
    r->headers_out.content_type_len = core->default_type.len;
    ngx_postgres_save_t *s = d->save;
    if (PQntuples(s->res) != 1 || PQnfields(s->res) != 1) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received %i value(s) instead of expected single value in location \"%V\"", PQntuples(s->res) * PQnfields(s->res), &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (PQgetisnull(s->res, 0, 0)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received NULL value in location \"%V\"", &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    size_t size = PQgetlength(s->res, 0, 0);
    if (!size) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received empty value in location \"%V\"", &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
    b->last = ngx_copy(b->last, PQgetvalue(s->res, 0, 0), size);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
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


static ngx_flag_t ngx_postgres_oid_is_string(Oid oid) {
    switch (oid) {
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
        case XIDOID:
            return 0;
        default: return 1;
    }
}


static ngx_int_t ngx_postgres_output_plain_csv(ngx_postgres_data_t *d, ngx_str_t content_type) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    r->headers_out.content_type = content_type;
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    ngx_postgres_save_t *s = d->save;
    if (!PQntuples(s->res) || !PQnfields(s->res)) return NGX_OK;
    size_t size = 0;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[d->query];
    ngx_http_upstream_t *u = r->upstream;
    if (query->output.header && !u->out_bufs) {
        size += PQnfields(s->res) - 1; // header delimiters
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = ngx_strlen(PQfname(s->res, col));
            if (query->output.quote) size++;
            if (query->output.escape) size += ngx_postgres_count((u_char *)PQfname(s->res, col), len, query->output.escape);
            else size += len;
            if (query->output.quote) size++;
        }
    }
    size += PQntuples(s->res) * (PQnfields(s->res) - 1); // value delimiters
    for (int row = 0; row < PQntuples(s->res); row++) {
        if (query->output.header || u->out_bufs || row > 0) size++;
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = PQgetlength(s->res, row, col);
            if (PQgetisnull(s->res, row, col)) size += query->output.null.len; else {
                if (!ngx_postgres_oid_is_string(PQftype(s->res, col)) && query->output.string) {
                    size += len;
                } else {
                    if (query->output.quote) size++;
                    if (len) {
                        if (query->output.escape) size += ngx_postgres_count((u_char *)PQgetvalue(s->res, row, col), len, query->output.escape);
                        else size += len;
                    }
                    if (query->output.quote) size++;
                }
            }
        }
    }
    if (!size) return NGX_OK;
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
    if (query->output.header && !u->out_bufs->next) {
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = ngx_strlen(PQfname(s->res, col));
            if (col > 0) *b->last++ = query->output.delimiter;
            if (query->output.quote) *b->last++ = query->output.quote;
            if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQfname(s->res, col), len, query->output.escape);
            else b->last = ngx_copy(b->last, PQfname(s->res, col), len);
            if (query->output.quote) *b->last++ = query->output.quote;
        }
    }
    for (int row = 0; row < PQntuples(s->res); row++) {
        if (query->output.header || u->out_bufs->next || row > 0) *b->last++ = '\n';
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = PQgetlength(s->res, row, col);
            if (col > 0) *b->last++ = query->output.delimiter;
            if (PQgetisnull(s->res, row, col)) b->last = ngx_copy(b->last, query->output.null.data, query->output.null.len); else {
                if (!ngx_postgres_oid_is_string(PQftype(s->res, col)) && query->output.string) {
                    if (len) b->last = ngx_copy(b->last, (u_char *)PQgetvalue(s->res, row, col), len);
                } else {
                    if (query->output.quote) *b->last++ = query->output.quote;
                    if (len) {
                        if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQgetvalue(s->res, row, col), len, query->output.escape);
                        else b->last = ngx_copy(b->last, (u_char *)PQgetvalue(s->res, row, col), len);
                    }
                    if (query->output.quote) *b->last++ = query->output.quote;
                }
            }
        }
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
}


ngx_int_t ngx_postgres_output_plain(ngx_postgres_data_t *d) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_plain_csv(d, (ngx_str_t)ngx_string("text/plain"));
}


ngx_int_t ngx_postgres_output_csv(ngx_postgres_data_t *d) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_plain_csv(d, (ngx_str_t)ngx_string("text/csv"));
}


ngx_int_t ngx_postgres_output_json(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    size_t size = 0;
    ngx_postgres_save_t *s = d->save;
    if (!PQntuples(s->res) || !PQnfields(s->res)) return NGX_OK;
    if (PQntuples(s->res) == 1 && PQnfields(s->res) == 1 && (PQftype(s->res, 0) == JSONOID || PQftype(s->res, 0) == JSONBOID)) size = PQgetlength(s->res, 0, 0); else {
        if (PQntuples(s->res) > 1) size += 2; // [] + \0
        for (int row = 0; row < PQntuples(s->res); row++) {
            size += sizeof("{}") - 1;
            for (int col = 0; col < PQnfields(s->res); col++) {
                int len = PQgetlength(s->res, row, col);
                if (PQgetisnull(s->res, row, col)) size += sizeof("null") - 1; else {
                    if (PQftype(s->res, col) == BOOLOID) switch (PQgetvalue(s->res, row, col)[0]) {
                        case 't': case 'T': size += sizeof("true") - 1; break;
                        case 'f': case 'F': size += sizeof("false") - 1; break;
                    } else if (!ngx_postgres_oid_is_string(PQftype(s->res, col))) size += len;
                    else size += sizeof("\"\"") - 1 + len + ngx_escape_json(NULL, (u_char *)PQgetvalue(s->res, row, col), len);
                }
            }
        }
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = ngx_strlen(PQfname(s->res, col));
            size += (len + 3 + ngx_escape_json(NULL, (u_char *)PQfname(s->res, col), len)) * PQntuples(s->res); // extra "":
        }
        size += PQntuples(s->res) * (PQnfields(s->res) - 1); /* col delimiters */
        size += PQntuples(s->res) - 1;                      /* row delimiters */
    }
    if (!size) return NGX_OK;
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
    if (PQntuples(s->res) == 1 && PQnfields(s->res) == 1 && (PQftype(s->res, 0) == JSONOID || PQftype(s->res, 0) == JSONBOID)) b->last = ngx_copy(b->last, PQgetvalue(s->res, 0, 0), PQgetlength(s->res, 0, 0)); else { /* fill data */
        if (PQntuples(s->res) > 1) b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (int row = 0; row < PQntuples(s->res); row++) {
            if (row > 0) b->last = ngx_copy(b->last, ",", 1);
            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (int col = 0; col < PQnfields(s->res); col++) {
                int len = PQgetlength(s->res, row, col);
                if (col > 0) b->last = ngx_copy(b->last, ",", 1);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQfname(s->res, col), ngx_strlen(PQfname(s->res, col)));
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);
                if (PQgetisnull(s->res, row, col)) b->last = ngx_copy(b->last, "null", sizeof("null") - 1); else {
                    if (PQftype(s->res, col) == BOOLOID) switch (PQgetvalue(s->res, row, col)[0]) {
                        case 't': case 'T': b->last = ngx_copy(b->last, "true", sizeof("true") - 1); break;
                        case 'f': case 'F': b->last = ngx_copy(b->last, "false", sizeof("false") - 1); break;
                    } else if (!ngx_postgres_oid_is_string(PQftype(s->res, col))) b->last = ngx_copy(b->last, PQgetvalue(s->res, row, col), len); else {
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                        if (len > 0) b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQgetvalue(s->res, row, col), len);
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                    }
                }
            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        if (PQntuples(s->res) > 1) b->last = ngx_copy(b->last, "]", sizeof("]") - 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
}


static rds_col_type_t ngx_postgres_rds_col_type(Oid col_type) {
    switch (col_type) {
        case INT8OID: return rds_col_type_bigint;
        case BITOID: return rds_col_type_bit;
        case VARBITOID: return rds_col_type_bit_varying;
        case BOOLOID: return rds_col_type_bool;
        case CHAROID: return rds_col_type_char;
        case NAMEOID: /* FALLTROUGH */
        case TEXTOID: /* FALLTROUGH */
        case VARCHAROID: return rds_col_type_varchar;
        case DATEOID: return rds_col_type_date;
        case FLOAT8OID: return rds_col_type_double;
        case INT4OID: return rds_col_type_integer;
        case INTERVALOID: return rds_col_type_interval;
        case NUMERICOID: return rds_col_type_decimal;
        case FLOAT4OID: return rds_col_type_real;
        case INT2OID: return rds_col_type_smallint;
        case TIMETZOID: return rds_col_type_time_with_time_zone;
        case TIMEOID: return rds_col_type_time;
        case TIMESTAMPTZOID: return rds_col_type_timestamp_with_time_zone;
        case TIMESTAMPOID: return rds_col_type_timestamp;
        case XMLOID: return rds_col_type_xml;
        case BYTEAOID: return rds_col_type_blob;
        default: return rds_col_type_unknown;
    }
}


static ngx_int_t ngx_postgres_output_rds(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_str_set(&r->headers_out.content_type, "application/x-resty-dbd-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    ngx_postgres_save_t *s = d->save;
//    if (!PQntuples(s->res) || !PQnfields(s->res)) return NGX_OK;
    const char *errstr = PQresultErrorMessage(s->res);
    size_t errstr_len = ngx_strlen(errstr);
    ngx_int_t ncmdTuples = NGX_ERROR;
    if (ngx_strncasecmp((u_char *)PQcmdStatus(s->res), (u_char *)"SELECT", sizeof("SELECT") - 1)) {
        char *affected = PQcmdTuples(s->res);
        size_t affected_len = ngx_strlen(affected);
        if (affected_len) ncmdTuples = ngx_atoi((u_char *)affected, affected_len);
    }
    size_t size = 0;
    size += sizeof(uint8_t)        /* endian type */
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
    size += PQnfields(s->res)
         * (sizeof(uint16_t)    /* standard column type */
            + sizeof(uint16_t)  /* driver-specific column type */
            + sizeof(uint16_t)  /* column name string length */
           )
         ;
    for (int col = 0; col < PQnfields(s->res); col++) size += ngx_strlen(PQfname(s->res, col));  /* column name string data */
    for (int row = 0; row < PQntuples(s->res); row++) {
        size += sizeof(uint8_t)                 /* row number */
             + (PQnfields(s->res) * sizeof(uint32_t))  /* field string length */
             ;
        for (int col = 0; col < PQnfields(s->res); col++) size += PQgetlength(s->res, row, col);  /* field string data */
    }
    size += sizeof(uint8_t);
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
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
    *(uint16_t *) b->last = (uint16_t) PQresultStatus(s->res);
    b->last += sizeof(uint16_t);
    *(uint16_t *) b->last = (uint16_t) errstr_len;
    b->last += sizeof(uint16_t);
    if (errstr_len) b->last = ngx_copy(b->last, (u_char *) errstr, errstr_len);
    *(uint64_t *) b->last = (uint64_t) (ncmdTuples == NGX_ERROR ? 0 : ncmdTuples);
    b->last += sizeof(uint64_t);
    *(uint64_t *) b->last = (uint64_t) PQoidValue(s->res);
    b->last += sizeof(uint64_t);
    *(uint16_t *) b->last = (uint16_t) PQnfields(s->res);
    b->last += sizeof(uint16_t);
    for (int col = 0; col < PQnfields(s->res); col++) {
        *(uint16_t *) b->last = (uint16_t) ngx_postgres_rds_col_type(PQftype(s->res, col));
        b->last += sizeof(uint16_t);
        *(uint16_t *) b->last = PQftype(s->res, col);
        b->last += sizeof(uint16_t);
        *(uint16_t *) b->last = (uint16_t) ngx_strlen(PQfname(s->res, col));
        b->last += sizeof(uint16_t);
        b->last = ngx_copy(b->last, PQfname(s->res, col), ngx_strlen(PQfname(s->res, col)));
    }
    for (int row = 0; row < PQntuples(s->res); row++) {
        *b->last++ = (uint8_t) 1; /* valid row */
        for (int col = 0; col < PQnfields(s->res); col++) {
            if (PQgetisnull(s->res, row, col)) {
                *(uint32_t *) b->last = (uint32_t) -1;
                 b->last += sizeof(uint32_t);
            } else {
                *(uint32_t *) b->last = (uint32_t) PQgetlength(s->res, row, col);
                b->last += sizeof(uint32_t);
                if (PQgetlength(s->res, row, col)) b->last = ngx_copy(b->last, PQgetvalue(s->res, row, col), PQgetlength(s->res, row, col));
            }
        }
    }
    *b->last++ = (uint8_t) 0; /* row terminator */
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
}


char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (!location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[location->query.nelts - 1];
    if (query->output.handler) return "duplicate";
    ngx_str_t *args = cf->args->elts;
    static const struct {
        ngx_str_t name;
        unsigned binary:1;
        ngx_int_t (*handler) (ngx_postgres_data_t *d);
    } h[] = {
        { ngx_string("none"), 0, NULL },
        { ngx_string("plain"), 0, ngx_postgres_output_plain },
        { ngx_string("csv"), 0, ngx_postgres_output_csv },
        { ngx_string("value"), 0, ngx_postgres_output_value },
        { ngx_string("binary"), 1, ngx_postgres_output_value },
        { ngx_string("json"), 0, ngx_postgres_output_json },
        { ngx_string("rds"), 0, ngx_postgres_output_rds },
        { ngx_null_string, 0, NULL }
    };
    ngx_uint_t i;
    for (i = 0; h[i].name.len; i++) if (h[i].name.len == args[1].len && !ngx_strncmp(h[i].name.data, args[1].data, args[1].len)) { query->output.handler = h[i].handler; break; }
    if (!h[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: format \"%V\" must be \"none\", \"plain\", \"csv\", \"value\", \"binary\", \"json\" or \"rds\"", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    query->output.binary = h[i].binary;
    query->output.header = 1;
    query->output.string = 1;
    if (query->output.handler == ngx_postgres_output_plain) {
        query->output.delimiter = '\t';
        ngx_str_set(&query->output.null, "\\N");
    } else if (query->output.handler == ngx_postgres_output_csv) {
        query->output.delimiter = ',';
        ngx_str_set(&query->output.null, "");
        query->output.quote = '"';
        query->output.escape = '"';
    }
    static const ngx_conf_enum_t e[] = {
        { ngx_string("off"), 0 },
        { ngx_string("no"), 0 },
        { ngx_string("false"), 0 },
        { ngx_string("on"), 1 },
        { ngx_string("yes"), 1 },
        { ngx_string("true"), 1 },
        { ngx_null_string, 0 }
    };
    ngx_uint_t j;
    for (i = 2; i < cf->args->nelts; i++) {
        if (query->output.handler == ngx_postgres_output_plain || query->output.handler == ngx_postgres_output_csv) {
            if (args[i].len > sizeof("delimiter=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
                args[i].len = args[i].len - (sizeof("delimiter=") - 1);
                if (!args[i].len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty \"delimiter\" value", &cmd->name); return NGX_CONF_ERROR; }
                if (args[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"delimiter\" value \"%V\" must be one character", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                args[i].data = &args[i].data[sizeof("delimiter=") - 1];
                query->output.delimiter = *args[i].data;
                continue;
            }
            if (args[i].len > sizeof("null=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
                args[i].len = args[i].len - (sizeof("null=") - 1);
                if (!(query->output.null.len = args[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty \"null\" value", &cmd->name); return NGX_CONF_ERROR; }
                args[i].data = &args[i].data[sizeof("null=") - 1];
                query->output.null.data = args[i].data;
                continue;
            }
            if (args[i].len > sizeof("header=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
                args[i].len = args[i].len - (sizeof("header=") - 1);
                args[i].data = &args[i].data[sizeof("header=") - 1];
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { query->output.header = e[j].value; break; }
                if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"header\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                continue;
            }
            if (args[i].len > sizeof("string=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
                args[i].len = args[i].len - (sizeof("string=") - 1);
                args[i].data = &args[i].data[sizeof("string=") - 1];
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { query->output.string = e[j].value; break; }
                if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"string\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                continue;
            }
            if (args[i].len > sizeof("single=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"single=", sizeof("single=") - 1)) {
                args[i].len = args[i].len - (sizeof("single=") - 1);
                args[i].data = &args[i].data[sizeof("single=") - 1];
                for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { query->output.single = e[j].value; break; }
                if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"single\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                continue;
            }
            if (args[i].len >= sizeof("quote=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
                args[i].len = args[i].len - (sizeof("quote=") - 1);
                if (!args[i].len) { query->output.quote = '\0'; continue; }
                else if (args[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"quote\" value \"%V\" must be one character", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                args[i].data = &args[i].data[sizeof("quote=") - 1];
                query->output.quote = *args[i].data;
                continue;
            }
            if (args[i].len >= sizeof("escape=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
                args[i].len = args[i].len - (sizeof("escape=") - 1);
                if (!args[i].len) { query->output.escape = '\0'; continue; }
                else if (args[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"escape\" value \"%V\" must be one character", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
                args[i].data = &args[i].data[sizeof("escape=") - 1];
                query->output.escape = *args[i].data;
                continue;
            }
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &args[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
