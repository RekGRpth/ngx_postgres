#include <postgresql/server/catalog/pg_type_d.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


ngx_int_t ngx_postgres_output_value(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_postgres_variable_output(r) != NGX_OK) return NGX_ERROR;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    if (result->ntuples != 1 || result->nfields != 1) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received %i value(s) instead of expected single value in location \"%V\"", result->ntuples * result->nfields, &core->name);
        pd->result.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    if (PQgetisnull(res, 0, 0)) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received NULL value in location \"%V\"", &core->name);
        pd->result.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    size_t size = PQgetlength(res, 0, 0);
    if (!size) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_output value\" received empty value in location \"%V\"", &core->name);
        pd->result.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_DONE;
    }
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = u->output.tag;
    b->last = ngx_copy(b->last, PQgetvalue(res, 0, 0), size);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->result.response = chain;
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_postgres_variable_output(r) != NGX_OK) return NGX_ERROR;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    if (!result->ntuples || !result->nfields) return NGX_DONE;
    size_t size = 0;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location->queries.elts;
    ngx_postgres_output_t *output = &query[pd->query.index].output;
    if (output->header) {
        size += result->nfields - 1; // header delimiters
        size++; // header new line
        for (ngx_uint_t col = 0; col < result->nfields; col++) {
            int len = ngx_strlen(PQfname(res, col));
            if (output->quote) size++;
            if (output->escape) size += ngx_postgres_count((u_char *)PQfname(res, col), len, output->escape);
            else size += len;
            if (location->append && !ngx_strstr(PQfname(res, col), "::")) {
                if (output->escape) size += ngx_postgres_count((u_char *)"::", sizeof("::") - 1, output->escape);
                else size += sizeof("::") - 1;
                Oid oid = PQftype(res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (output->escape) size += ngx_postgres_count((u_char *)type, ngx_strlen(type), output->escape);
                    else size += ngx_strlen(type);
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (output->escape) size += ngx_postgres_count((u_char *)type, len, output->escape);
                    else size += len;
                }
            }
            if (output->quote) size++;
        }
    }
    size += result->ntuples * (result->nfields - 1); // value delimiters
    size += result->ntuples - 1; // value new line
    for (ngx_uint_t row = 0; row < result->ntuples; row++) for (ngx_uint_t col = 0; col < result->nfields; col++) {
        int len = PQgetlength(res, row, col);
        if (PQgetisnull(res, row, col)) size += output->null.len; else switch (PQftype(res, col)) {
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
            case XIDOID: if (output->string) {
                size += len;
                break;
            } // fall through
            default: {
                if (output->quote) size++;
                if (len) {
                    if (output->escape) size += ngx_postgres_count((u_char *)PQgetvalue(res, row, col), len, output->escape);
                    else size += len;
                }
                if (output->quote) size++;
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
    b->tag = u->output.tag;
    if (output->header) {
        for (ngx_uint_t col = 0; col < result->nfields; col++) {
            int len = ngx_strlen(PQfname(res, col));
            if (col > 0) *b->last++ = output->delimiter;
            if (output->quote) *b->last++ = output->quote;
            if (output->escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQfname(res, col), len, output->escape);
            else b->last = ngx_copy(b->last, PQfname(res, col), len);
            if (location->append && !ngx_strstr(PQfname(res, col), "::")) {
                if (output->escape) b->last = ngx_postgres_escape(b->last, (u_char *)"::", sizeof("::") - 1, output->escape);
                else b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                Oid oid = PQftype(res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (output->escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, ngx_strlen(type), output->escape);
                    else b->last = ngx_copy(b->last, type, ngx_strlen(type));
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (output->escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, len, output->escape);
                    else b->last = ngx_copy(b->last, type, len);
                }
            }
            if (output->quote) *b->last++ = output->quote;
        }
        *b->last++ = '\n';
    }
    for (ngx_uint_t row = 0; row < result->ntuples; row++) {
        if (row > 0) *b->last++ = '\n';
        for (ngx_uint_t col = 0; col < result->nfields; col++) {
            int len = PQgetlength(res, row, col);
            if (col > 0) *b->last++ = output->delimiter;
            if (PQgetisnull(res, row, col)) b->last = ngx_copy(b->last, output->null.data, output->null.len); else switch (PQftype(res, col)) {
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
                case XIDOID: if (output->string) {
                    if (len) b->last = ngx_copy(b->last, (u_char *)PQgetvalue(res, row, col), len);
                    break;
                } // fall through
                default: {
                    if (output->quote) *b->last++ = output->quote;
                    if (len) {
                        if (output->escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQgetvalue(res, row, col), len, output->escape);
                        else b->last = ngx_copy(b->last, (u_char *)PQgetvalue(res, row, col), len);
                    }
                    if (output->quote) *b->last++ = output->quote;
                } break;
            }
        }
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->result.response = chain;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_output_text(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_text_csv(r);
}


static ngx_int_t ngx_postgres_output_csv(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_text_csv(r);
}


ngx_int_t ngx_postgres_output_json(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_postgres_variable_output(r) != NGX_OK) return NGX_ERROR;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    size_t size = 0;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    if (result->ntuples == 1 && result->nfields == 1 && (PQftype(res, 0) == JSONOID || PQftype(res, 0) == JSONBOID)) size = PQgetlength(res, 0, 0); else {
        if (result->ntuples > 1) size += 2; // [] + \0
        for (ngx_uint_t row = 0; row < result->ntuples; row++) {
            size += sizeof("{}") - 1;
            for (ngx_uint_t col = 0; col < result->nfields; col++) {
                int len = PQgetlength(res, row, col);
                if (PQgetisnull(res, row, col)) size += sizeof("null") - 1; else switch (PQftype(res, col)) {
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
                    case BOOLOID: switch (PQgetvalue(res, row, col)[0]) {
                        case 't': case 'T': size += sizeof("true") - 1; break;
                        case 'f': case 'F': size += sizeof("false") - 1; break;
                    } break;
                    default: size += sizeof("\"\"") - 1 + len + ngx_escape_json(NULL, (u_char *)PQgetvalue(res, row, col), len); break;
                }
            }
        }
        for (ngx_uint_t col = 0; col < result->nfields; col++) {
            int len = ngx_strlen(PQfname(res, col));
            size += (len + 3 + ngx_escape_json(NULL, (u_char *)PQfname(res, col), len)) * result->ntuples; // extra "":
            if (location->append && !ngx_strstr(PQfname(res, col), "::")) {
                size += 2 * result->ntuples;
                Oid oid = PQftype(res, col);
                const char *type = PQftypeMy(oid);
                if (type) size += ngx_strlen(type) * result->ntuples; else size += snprintf(NULL, 0, "%i", oid) * result->ntuples;
            }
        }
        size += result->ntuples * (result->nfields - 1); /* col delimiters */
        size += result->ntuples - 1;                      /* row delimiters */
    }
    if (!result->ntuples || !size) return NGX_DONE;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_create_temp_buf"); return NGX_ERROR; }
    ngx_chain_t *chain = ngx_alloc_chain_link(r->pool);
    if (!chain) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_alloc_chain_link"); return NGX_ERROR; }
    chain->buf = b;
    b->memory = 1;
    b->tag = u->output.tag;
    if (result->ntuples == 1 && result->nfields == 1 && (PQftype(res, 0) == JSONOID || PQftype(res, 0) == JSONBOID)) b->last = ngx_copy(b->last, PQgetvalue(res, 0, 0), PQgetlength(res, 0, 0)); else { /* fill data */
        if (result->ntuples > 1) b->last = ngx_copy(b->last, "[", sizeof("[") - 1);
        for (ngx_uint_t row = 0; row < result->ntuples; row++) {
            if (row > 0) b->last = ngx_copy(b->last, ",", 1);
            b->last = ngx_copy(b->last, "{", sizeof("{") - 1);
            for (ngx_uint_t col = 0; col < result->nfields; col++) {
                int len = PQgetlength(res, row, col);
                if (col > 0) b->last = ngx_copy(b->last, ",", 1);
                b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQfname(res, col), ngx_strlen(PQfname(res, col)));
                if (location->append && !ngx_strstr(PQfname(res, col), "::")) {
                    b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                    Oid oid = PQftype(res, col);
                    const char *type = PQftypeMy(oid);
                    if (type) b->last = ngx_copy(b->last, type, ngx_strlen(type)); else {
                        size_t len = snprintf(NULL, 0, "%i", oid);
                        char type[len + 1];
                        snprintf(type, len + 1, "%i", oid);
                        b->last = ngx_copy(b->last, type, len);
                    }
                }
                b->last = ngx_copy(b->last, "\":", sizeof("\":") - 1);
                if (PQgetisnull(res, row, col)) b->last = ngx_copy(b->last, "null", sizeof("null") - 1); else switch (PQftype(res, col)) {
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
                    case XIDOID: b->last = ngx_copy(b->last, PQgetvalue(res, row, col), len); break;
                    case BOOLOID: switch (PQgetvalue(res, row, col)[0]) {
                        case 't': case 'T': b->last = ngx_copy(b->last, "true", sizeof("true") - 1); break;
                        case 'f': case 'F': b->last = ngx_copy(b->last, "false", sizeof("false") - 1); break;
                    } break;
                    default: {
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                        if (len > 0) b->last = (u_char *)ngx_escape_json(b->last, (u_char *)PQgetvalue(res, row, col), len);
                        b->last = ngx_copy(b->last, "\"", sizeof("\"") - 1);
                    } break;
                }
            }
            b->last = ngx_copy(b->last, "}", sizeof("}") - 1);
        }
        if (result->ntuples > 1) b->last = ngx_copy(b->last, "]", sizeof("]") - 1);
    }
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    chain->next = NULL;
    pd->result.response = chain;
    return NGX_DONE;
}


void ngx_postgres_output_chain(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!r->header_sent) {
        ngx_http_clear_content_length(r);
        ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        r->headers_out.status = pd->result.status ? ngx_abs(pd->result.status) : NGX_HTTP_OK;
        ngx_postgres_common_t *pdc = &pd->common;
        if (pdc->charset.len) r->headers_out.charset = pdc->charset;
        ngx_postgres_query_t *query = location->queries.elts;
        ngx_postgres_output_t *output = &query[pd->query.index].output;
        if (output->handler == &ngx_postgres_output_json) {
            ngx_str_set(&r->headers_out.content_type, "application/json");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (output->handler == &ngx_postgres_output_text) {
            ngx_str_set(&r->headers_out.content_type, "text/plain");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (output->handler == &ngx_postgres_output_csv) {
            ngx_str_set(&r->headers_out.content_type, "text/csv");
            r->headers_out.content_type_len = r->headers_out.content_type.len;
        } else if (output->handler) {
            ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            r->headers_out.content_type = core->default_type;
            r->headers_out.content_type_len = core->default_type.len;
        }
        r->headers_out.content_type_lowcase = NULL;
        if (pd->result.response) r->headers_out.content_length_n = pd->result.response->buf->end - pd->result.response->buf->start;
        ngx_int_t rc = ngx_http_send_header(r);
        u->header_sent = r->header_sent;
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return;
    }
    if (!pd->result.response) return;
    ngx_int_t rc = ngx_http_output_filter(r, pd->result.response);
    if (rc == NGX_ERROR || rc > NGX_OK) return;
    ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs, &pd->result.response, u->output.tag);
}


char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (location->query == NGX_CONF_UNSET_PTR) return "must defined after \"postgres_query\" directive";
    ngx_postgres_output_t *output = &location->query->output;
    if (output->handler) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    static const struct {
        ngx_str_t name;
        unsigned binary:1;
        ngx_postgres_handler_pt handler;
    } e[] = {
        { ngx_string("none"), 0, NULL },
        { ngx_string("text"), 0, ngx_postgres_output_text },
        { ngx_string("csv"), 0, ngx_postgres_output_csv },
        { ngx_string("value"), 0, ngx_postgres_output_value },
        { ngx_string("binary"), 1, ngx_postgres_output_value },
        { ngx_string("json"), 0, ngx_postgres_output_json },
        { ngx_null_string, 0, NULL }
    };
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[1].len && !ngx_strncasecmp(e[i].name.data, elts[1].data, elts[1].len)) { output->handler = e[i].handler; break; }
    if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: format \"%V\" must be \"none\", \"text\", \"csv\", \"value\", \"binary\" or \"json\"", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    output->binary = e[i].binary;
    output->header = 1;
    output->string = 1;
    if (output->handler == ngx_postgres_output_text) {
        output->delimiter = '\t';
        ngx_str_set(&output->null, "\\N");
    } else if (output->handler == ngx_postgres_output_csv) {
        output->delimiter = ',';
        ngx_str_set(&output->null, "");
        output->quote = '"';
        output->escape = '"';
    }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("delimiter=") - 1);
            if (!elts[i].len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty \"delimiter\" value", &cmd->name); return NGX_CONF_ERROR; }
            if (elts[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"delimiter\" value \"%V\" must be one character", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            elts[i].data = &elts[i].data[sizeof("delimiter=") - 1];
            output->delimiter = *elts[i].data;
        } else if (elts[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("null=") - 1);
            if (!(output->null.len = elts[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty \"null\" value", &cmd->name); return NGX_CONF_ERROR; }
            elts[i].data = &elts[i].data[sizeof("null=") - 1];
            output->null.data = elts[i].data;
        } else if (elts[i].len > sizeof("append=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"append=", sizeof("append=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("append=") - 1);
            elts[i].data = &elts[i].data[sizeof("append=") - 1];
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
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location->append = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"append\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else if (elts[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("header=") - 1);
            elts[i].data = &elts[i].data[sizeof("header=") - 1];
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
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { output->header = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"header\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else if (elts[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("string=") - 1);
            elts[i].data = &elts[i].data[sizeof("string=") - 1];
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
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { output->string = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"string\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else if (elts[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("quote=") - 1);
            if (!elts[i].len) { output->quote = '\0'; continue; }
            else if (elts[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"quote\" value \"%V\" must be one character", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            elts[i].data = &elts[i].data[sizeof("quote=") - 1];
            output->quote = *elts[i].data;
        } else if (elts[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("escape=") - 1);
            if (!elts[i].len) { output->escape = '\0'; continue; }
            else if (elts[i].len > 1) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"escape\" value \"%V\" must be one character", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            elts[i].data = &elts[i].data[sizeof("escape=") - 1];
            output->escape = *elts[i].data;
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}
