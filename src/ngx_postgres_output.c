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


static ngx_int_t ngx_postgres_output_value(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (pd->result.ntuples != 1 || pd->result.nfields != 1) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received %i value(s) instead of expected single value in location \"%V\"", pd->result.ntuples * pd->result.nfields, &core_loc_conf->name);
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    if (PQgetisnull(pd->result.res, 0, 0)) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received NULL value in location \"%V\"", &core_loc_conf->name);
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    size_t size = PQgetlength(pd->result.res, 0, 0);
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
    b->last = ngx_copy(b->last, PQgetvalue(pd->result.res, 0, 0), size);
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


static const char *PQftypeMy(Oid oid) {
    switch (oid) {
        case BOOLOID: return "bool";
        case BYTEAOID: return "bytea";
        case CHAROID: return "char";
        case NAMEOID: return "name";
        case INT8OID: return "int8";
        case INT2OID: return "int2";
        case INT2VECTOROID: return "int2vector";
        case INT4OID: return "int4";
        case REGPROCOID: return "regproc";
        case TEXTOID: return "text";
        case OIDOID: return "oid";
        case TIDOID: return "tid";
        case XIDOID: return "xid";
        case CIDOID: return "cid";
        case OIDVECTOROID: return "oidvector";
        case JSONOID: return "json";
        case XMLOID: return "xml";
        case PGNODETREEOID: return "pgnodetree";
        case PGNDISTINCTOID: return "pgndistinct";
        case PGDEPENDENCIESOID: return "pgdependencies";
        case PGMCVLISTOID: return "pgmcvlist";
        case PGDDLCOMMANDOID: return "pgddlcommand";
        case POINTOID: return "point";
        case LSEGOID: return "lseg";
        case PATHOID: return "path";
        case BOXOID: return "box";
        case POLYGONOID: return "polygon";
        case LINEOID: return "line";
        case FLOAT4OID: return "float4";
        case FLOAT8OID: return "float8";
        case UNKNOWNOID: return "unknown";
        case CIRCLEOID: return "circle";
        case CASHOID: return "cash";
        case MACADDROID: return "macaddr";
        case INETOID: return "inet";
        case CIDROID: return "cidr";
        case MACADDR8OID: return "macaddr8";
        case ACLITEMOID: return "aclitem";
        case BPCHAROID: return "bpchar";
        case VARCHAROID: return "varchar";
        case DATEOID: return "date";
        case TIMEOID: return "time";
        case TIMESTAMPOID: return "timestamp";
        case TIMESTAMPTZOID: return "timestamptz";
        case INTERVALOID: return "interval";
        case TIMETZOID: return "timetz";
        case BITOID: return "bit";
        case VARBITOID: return "varbit";
        case NUMERICOID: return "numeric";
        case REFCURSOROID: return "refcursor";
        case REGPROCEDUREOID: return "regprocedure";
        case REGOPEROID: return "regoper";
        case REGOPERATOROID: return "regoperator";
        case REGCLASSOID: return "regclass";
        case REGTYPEOID: return "regtype";
        case REGROLEOID: return "regrole";
        case REGNAMESPACEOID: return "regnamespace";
        case UUIDOID: return "uuid";
        case LSNOID: return "lsn";
        case TSVECTOROID: return "tsvector";
        case GTSVECTOROID: return "gtsvector";
        case TSQUERYOID: return "tsquery";
        case REGCONFIGOID: return "regconfig";
        case REGDICTIONARYOID: return "regdictionary";
        case JSONBOID: return "jsonb";
        case JSONPATHOID: return "jsonpath";
        case TXID_SNAPSHOTOID: return "txid_snapshot";
        case INT4RANGEOID: return "int4range";
        case NUMRANGEOID: return "numrange";
        case TSRANGEOID: return "tsrange";
        case TSTZRANGEOID: return "tstzrange";
        case DATERANGEOID: return "daterange";
        case INT8RANGEOID: return "int8range";
        case RECORDOID: return "record";
        case RECORDARRAYOID: return "recordarray";
        case CSTRINGOID: return "cstring";
        case ANYOID: return "any";
        case ANYARRAYOID: return "anyarray";
        case VOIDOID: return "void";
        case TRIGGEROID: return "trigger";
        case EVTTRIGGEROID: return "evttrigger";
        case LANGUAGE_HANDLEROID: return "language_handler";
        case INTERNALOID: return "internal";
        case OPAQUEOID: return "opaque";
        case ANYELEMENTOID: return "anyelement";
        case ANYNONARRAYOID: return "anynonarray";
        case ANYENUMOID: return "anyenum";
        case FDW_HANDLEROID: return "fdw_handler";
        case INDEX_AM_HANDLEROID: return "index_am_handler";
        case TSM_HANDLEROID: return "tsm_handler";
        case TABLE_AM_HANDLEROID: return "table_am_handler";
        case ANYRANGEOID: return "anyrange";
        case BOOLARRAYOID: return "boolarray";
        case BYTEAARRAYOID: return "byteaarray";
        case CHARARRAYOID: return "chararray";
        case NAMEARRAYOID: return "namearray";
        case INT8ARRAYOID: return "int8array";
        case INT2ARRAYOID: return "int2array";
        case INT2VECTORARRAYOID: return "int2vectorarray";
        case INT4ARRAYOID: return "int4array";
        case REGPROCARRAYOID: return "regprocarray";
        case TEXTARRAYOID: return "textarray";
        case OIDARRAYOID: return "oidarray";
        case TIDARRAYOID: return "tidarray";
        case XIDARRAYOID: return "xidarray";
        case CIDARRAYOID: return "cidarray";
        case OIDVECTORARRAYOID: return "oidvectorarray";
        case JSONARRAYOID: return "jsonarray";
        case XMLARRAYOID: return "xmlarray";
        case POINTARRAYOID: return "pointarray";
        case LSEGARRAYOID: return "lsegarray";
        case PATHARRAYOID: return "patharray";
        case BOXARRAYOID: return "boxarray";
        case POLYGONARRAYOID: return "polygonarray";
        case LINEARRAYOID: return "linearray";
        case FLOAT4ARRAYOID: return "float4array";
        case FLOAT8ARRAYOID: return "float8array";
        case CIRCLEARRAYOID: return "circlearray";
        case MONEYARRAYOID: return "moneyarray";
        case MACADDRARRAYOID: return "macaddrarray";
        case INETARRAYOID: return "inetarray";
        case CIDRARRAYOID: return "cidrarray";
        case MACADDR8ARRAYOID: return "macaddr8array";
        case ACLITEMARRAYOID: return "aclitemarray";
        case BPCHARARRAYOID: return "bpchararray";
        case VARCHARARRAYOID: return "varchararray";
        case DATEARRAYOID: return "datearray";
        case TIMEARRAYOID: return "timearray";
        case TIMESTAMPARRAYOID: return "timestamparray";
        case TIMESTAMPTZARRAYOID: return "timestamptzarray";
        case INTERVALARRAYOID: return "intervalarray";
        case TIMETZARRAYOID: return "timetzarray";
        case BITARRAYOID: return "bitarray";
        case VARBITARRAYOID: return "varbitarray";
        case NUMERICARRAYOID: return "numericarray";
        case REFCURSORARRAYOID: return "refcursorarray";
        case REGPROCEDUREARRAYOID: return "regprocedurearray";
        case REGOPERARRAYOID: return "regoperarray";
        case REGOPERATORARRAYOID: return "regoperatorarray";
        case REGCLASSARRAYOID: return "regclassarray";
        case REGTYPEARRAYOID: return "regtypearray";
        case REGROLEARRAYOID: return "regrolearray";
        case REGNAMESPACEARRAYOID: return "regnamespacearray";
        case UUIDARRAYOID: return "uuidarray";
        case PG_LSNARRAYOID: return "pg_lsnarray";
        case TSVECTORARRAYOID: return "tsvectorarray";
        case GTSVECTORARRAYOID: return "gtsvectorarray";
        case TSQUERYARRAYOID: return "tsqueryarray";
        case REGCONFIGARRAYOID: return "regconfigarray";
        case REGDICTIONARYARRAYOID: return "regdictionaryarray";
        case JSONBARRAYOID: return "jsonbarray";
        case JSONPATHARRAYOID: return "jsonpatharray";
        case TXID_SNAPSHOTARRAYOID: return "txid_snapshotarray";
        case INT4RANGEARRAYOID: return "int4rangearray";
        case NUMRANGEARRAYOID: return "numrangearray";
        case TSRANGEARRAYOID: return "tsrangearray";
        case TSTZRANGEARRAYOID: return "tstzrangearray";
        case DATERANGEARRAYOID: return "daterangearray";
        case INT8RANGEARRAYOID: return "int8rangearray";
        case CSTRINGARRAYOID: return "cstringarray";
        default: return NULL;
    }
}


static ngx_int_t ngx_postgres_output_text_csv(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (!pd->result.ntuples || !pd->result.nfields) return NGX_DONE;
    size_t size = 0;
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location_conf->output.header) {
        size += pd->result.nfields - 1; // header delimiters
        size++; // header new line
        for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
            int len = ngx_strlen(PQfname(pd->result.res, col));
            if (location_conf->output.quote) size++;
            if (location_conf->output.escape) size += ngx_postgres_count((u_char *)PQfname(pd->result.res, col), len, location_conf->output.escape);
            else size += len;
            if (location_conf->output.append && !ngx_strstr(PQfname(pd->result.res, col), "::")) {
                if (location_conf->output.escape) size += ngx_postgres_count((u_char *)"::", sizeof("::") - 1, location_conf->output.escape);
                else size += sizeof("::") - 1;
                Oid oid = PQftype(pd->result.res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (location_conf->output.escape) size += ngx_postgres_count((u_char *)type, ngx_strlen(type), location_conf->output.escape);
                    else size += ngx_strlen(type);
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (location_conf->output.escape) size += ngx_postgres_count((u_char *)type, len, location_conf->output.escape);
                    else size += len;
                }
            }
            if (location_conf->output.quote) size++;
        }
    }
    size += pd->result.ntuples * (pd->result.nfields - 1); // value delimiters
    size += pd->result.ntuples - 1; // value new line
    for (ngx_int_t row = 0; row < pd->result.ntuples; row++) for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
        int len = PQgetlength(pd->result.res, row, col);
        if (PQgetisnull(pd->result.res, row, col)) size += location_conf->output.null.len; else switch (PQftype(pd->result.res, col)) {
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
                size += len;
                break;
            } // fall through
            default: {
                if (location_conf->output.quote) size++;
                if (len) {
                    if (location_conf->output.escape) size += ngx_postgres_count((u_char *)PQgetvalue(pd->result.res, row, col), len, location_conf->output.escape);
                    else size += len;
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
        for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
            int len = ngx_strlen(PQfname(pd->result.res, col));
            if (col > 0) *b->last++ = location_conf->output.delimiter;
            if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
            if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQfname(pd->result.res, col), len, location_conf->output.escape);
            else b->last = ngx_copy(b->last, PQfname(pd->result.res, col), len);
            if (location_conf->output.append && !ngx_strstr(PQfname(pd->result.res, col), "::")) {
                if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)"::", sizeof("::") - 1, location_conf->output.escape);
                else b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                Oid oid = PQftype(pd->result.res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, ngx_strlen(type), location_conf->output.escape);
                    else b->last = ngx_copy(b->last, type, ngx_strlen(type));
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, len, location_conf->output.escape);
                    else b->last = ngx_copy(b->last, type, len);
                }
            }
            if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
        }
        *b->last++ = '\n';
    }
    for (ngx_int_t row = 0; row < pd->result.ntuples; row++) {
        if (row > 0) *b->last++ = '\n';
        for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
            int len = PQgetlength(pd->result.res, row, col);
            if (col > 0) *b->last++ = location_conf->output.delimiter;
            if (PQgetisnull(pd->result.res, row, col)) b->last = ngx_copy(b->last, location_conf->output.null.data, location_conf->output.null.len); else switch (PQftype(pd->result.res, col)) {
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
                    if (len) b->last = ngx_copy(b->last, (u_char *)PQgetvalue(pd->result.res, row, col), len);
                    break;
                } // fall through
                default: {
                    if (location_conf->output.quote) *b->last++ = location_conf->output.quote;
                    if (len) {
                        if (location_conf->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQgetvalue(pd->result.res, row, col), len, location_conf->output.escape);
                        else b->last = ngx_copy(b->last, (u_char *)PQgetvalue(pd->result.res, row, col), len);
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


static ngx_int_t ngx_postgres_output_text(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


static ngx_int_t ngx_postgres_output_csv(ngx_http_request_t *r) {
    return ngx_postgres_output_text_csv(r);
}


static ngx_int_t ngx_postgres_output_json(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    size_t size = 0;
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (pd->result.ntuples == 1 && pd->result.nfields == 1 && (PQftype(pd->result.res, 0) == JSONOID || PQftype(pd->result.res, 0) == JSONBOID)) size = PQgetlength(pd->result.res, 0, 0); else {
        if (pd->result.ntuples > 1) size += 2; // [] + \0
        for (ngx_int_t row = 0; row < pd->result.ntuples; row++) {
            size += sizeof("{}") - 1;
            for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
                int len = PQgetlength(pd->result.res, row, col);
                if (PQgetisnull(pd->result.res, row, col)) size += sizeof("null") - 1; else switch (PQftype(pd->result.res, col)) {
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
                    case XIDOID: size += len; break;
                    case BOOLOID: switch (PQgetvalue(pd->result.res, row, col)[0]) {
                        case 't': case 'T': size += sizeof("true") - 1; break;
                        case 'f': case 'F': size += sizeof("false") - 1; break;
                    } break;
                    default: size += sizeof("\"\"") - 1 + len + ngx_escape_json(NULL, (u_char *)PQgetvalue(pd->result.res, row, col), len); break;
                }
            }
        }
        for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
            int len = ngx_strlen(PQfname(pd->result.res, col));
            size += (len + 3 + ngx_escape_json(NULL, (u_char *)PQfname(pd->result.res, col), len)) * pd->result.ntuples; // extra "":
            if (location_conf->output.append && !ngx_strstr(PQfname(pd->result.res, col), "::")) {
                size += 2 * pd->result.ntuples;
                Oid oid = PQftype(pd->result.res, col);
                const char *type = PQftypeMy(oid);
                if (type) size += ngx_strlen(type) * pd->result.ntuples; else size += snprintf(NULL, 0, "%i", oid) * pd->result.ntuples;
            }
        }
        size += pd->result.ntuples * (pd->result.nfields - 1); /* col delimiters */
        size += pd->result.ntuples - 1;                      /* row delimiters */
    }
    if (!pd->result.ntuples || !size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = r->upstream->output.tag;
    if (pd->result.ntuples == 1 && pd->result.nfields == 1 && (PQftype(pd->result.res, 0) == JSONOID || PQftype(pd->result.res, 0) == JSONBOID)) b->last = ngx_copy(b->last, PQgetvalue(pd->result.res, 0, 0), PQgetlength(pd->result.res, 0, 0)); else { /* fill data */
        if (pd->result.ntuples > 1) b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (ngx_int_t row = 0; row < pd->result.ntuples; row++) {
            if (row > 0) b->last = ngx_copy(b->last, ",", 1);
            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (ngx_int_t col = 0; col < pd->result.nfields; col++) {
                int len = PQgetlength(pd->result.res, row, col);
                if (col > 0) b->last = ngx_copy(b->last, ",", 1);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQfname(pd->result.res, col), ngx_strlen(PQfname(pd->result.res, col)));
                if (location_conf->output.append && !ngx_strstr(PQfname(pd->result.res, col), "::")) {
                    b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                    Oid oid = PQftype(pd->result.res, col);
                    const char *type = PQftypeMy(oid);
                    if (type) b->last = ngx_copy(b->last, type, ngx_strlen(type)); else {
                        size_t len = snprintf(NULL, 0, "%i", oid);
                        char type[len + 1];
                        snprintf(type, len + 1, "%i", oid);
                        b->last = ngx_copy(b->last, type, len);
                    }
                }
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);
                if (PQgetisnull(pd->result.res, row, col)) b->last = ngx_copy(b->last, "null", sizeof("null") - 1); else switch (PQftype(pd->result.res, col)) {
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
                    case XIDOID: b->last = ngx_copy(b->last, PQgetvalue(pd->result.res, row, col), len); break;
                    case BOOLOID: switch (PQgetvalue(pd->result.res, row, col)[0]) {
                        case 't': case 'T': b->last = ngx_copy(b->last, "true", sizeof("true") - 1); break;
                        case 'f': case 'F': b->last = ngx_copy(b->last, "false", sizeof("false") - 1); break;
                    } break;
                    default: {
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                        if (len > 0) b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQgetvalue(pd->result.res, row, col), len);
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                    } break;
                }
            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        if (pd->result.ntuples > 1) b->last = ngx_copy(b->last, "]", sizeof("]") - 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->response = chain; /* set output response */
    return NGX_DONE;
}


ngx_int_t ngx_postgres_output_chain(ngx_http_request_t *r) {
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    if (!r->header_sent) {
        ngx_http_clear_content_length(r);
        ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        r->headers_out.status = pd->status ? ngx_abs(pd->status) : NGX_HTTP_OK;
        ngx_postgres_data_t *pd = r->upstream->peer.data;
        if (pd->result.charset.len) r->headers_out.charset = pd->result.charset;
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


struct ngx_postgres_output_enum_t {
    ngx_str_t name;
    unsigned binary:1;
    ngx_postgres_output_handler_pt handler;
} ngx_postgres_output_handlers[] = {
    { ngx_string("none"), 0, NULL },
    { ngx_string("text"), 0, ngx_postgres_output_text },
    { ngx_string("csv"), 0, ngx_postgres_output_csv },
    { ngx_string("value"), 0, ngx_postgres_output_value },
    { ngx_string("binary"), 1, ngx_postgres_output_value },
    { ngx_string("json"), 0, ngx_postgres_output_json },
    { ngx_null_string, 0, NULL }
};


ngx_conf_enum_t ngx_postgres_output_options[] = {
    { ngx_string("off"), 0 },
    { ngx_string("no"), 0 },
    { ngx_string("false"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("yes"), 1 },
    { ngx_string("true"), 1 },
    { ngx_null_string, 0 }
};


char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->output.handler) return "is duplicate";
    struct ngx_postgres_output_enum_t *e = ngx_postgres_output_handlers;
    ngx_str_t *elts = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[1].len && !ngx_strncasecmp(e[i].name.data, elts[1].data, elts[1].len)) { location_conf->output.handler = e[i].handler; break; }
    if (!e[i].name.len) return "invalid output format";
    location_conf->output.binary = e[i].binary;
    if (location_conf->output.handler == ngx_postgres_output_text) {
        location_conf->output.delimiter = '\t';
        ngx_str_set(&location_conf->output.null, "\\N");
    } else if (location_conf->output.handler == ngx_postgres_output_csv) {
        location_conf->output.delimiter = ',';
        ngx_str_set(&location_conf->output.null, "");
        location_conf->output.quote = '"';
        location_conf->output.escape = '"';
    }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("delimiter=") - 1);
            if (!elts[i].len || elts[i].len > 1) return "invalid delimiter";
            elts[i].data = &elts[i].data[sizeof("delimiter=") - 1];
            location_conf->output.delimiter = *elts[i].data;
        } else if (elts[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("null=") - 1);
            if (!(location_conf->output.null.len = elts[i].len)) return "invalid null";
            elts[i].data = &elts[i].data[sizeof("null=") - 1];
            location_conf->output.null.data = elts[i].data;
        } else if (elts[i].len > sizeof("append=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"append=", sizeof("append=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("append=") - 1);
            elts[i].data = &elts[i].data[sizeof("append=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.append = e[j].value; break; }
            if (!e[j].name.len) return "invalid append";
        } else if (elts[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("header=") - 1);
            elts[i].data = &elts[i].data[sizeof("header=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.header = e[j].value; break; }
            if (!e[j].name.len) return "invalid header";
        } else if (elts[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("string=") - 1);
            elts[i].data = &elts[i].data[sizeof("string=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.string = e[j].value; break; }
            if (!e[j].name.len) return "invalid string";
        } else if (elts[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("quote=") - 1);
            if (!elts[i].len) { location_conf->output.quote = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid quote";
            elts[i].data = &elts[i].data[sizeof("quote=") - 1];
            location_conf->output.quote = *elts[i].data;
        } else if (elts[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("escape=") - 1);
            if (!elts[i].len) { location_conf->output.escape = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid escape";
            elts[i].data = &elts[i].data[sizeof("escape=") - 1];
            location_conf->output.escape = *elts[i].data;
        } else return "invalid parameter";
    }
    return NGX_CONF_OK;
}
