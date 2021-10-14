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


ngx_int_t ngx_postgres_output_value(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    r->headers_out.content_type = core->default_type;
    r->headers_out.content_type_len = core->default_type.len;
    if (PQntuples(s->res) != 1 || PQnfields(s->res) != 1) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_output value\" received %i value(s) instead of expected single value in location \"%V\"", PQntuples(s->res) * PQnfields(s->res), &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (PQgetisnull(s->res, 0, 0)) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_output value\" received NULL value in location \"%V\"", &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    size_t size = PQgetlength(s->res, 0, 0);
    if (!size) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_output value\" received empty value in location \"%V\"", &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
    b->last = ngx_copy(b->last, PQgetvalue(s->res, 0, 0), size);
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
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
#if (PG_VERSION_NUM >= 140000)
        case PG_NODE_TREEOID: return "pg_node_tree";
        case PG_NDISTINCTOID: return "pg_ndistinct";
        case PG_DEPENDENCIESOID: return "pg_dependencies";
        case PG_MCV_LISTOID: return "pg_mcv_list";
        case PG_DDL_COMMANDOID: return "pg_ddl_command";
#else
        case PGNODETREEOID: return "pgnodetree";
        case PGNDISTINCTOID: return "pgndistinct";
        case PGDEPENDENCIESOID: return "pgdependencies";
        case PGMCVLISTOID: return "pgmcvlist";
        case PGDDLCOMMANDOID: return "pgddlcommand";
#endif
#if (PG_VERSION_NUM >= 130000)
        case XID8OID: return "xid8";
#endif
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
#if (PG_VERSION_NUM >= 140000)
        case MONEYOID: return "money";
#endif
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
#if (PG_VERSION_NUM >= 130000)
        case REGCOLLATIONOID: return "regcollation";
#endif
        case REGTYPEOID: return "regtype";
        case REGROLEOID: return "regrole";
        case REGNAMESPACEOID: return "regnamespace";
        case UUIDOID: return "uuid";
#if (PG_VERSION_NUM >= 140000)
        case PG_LSNOID: return "pg_lsn";
#endif
        case LSNOID: return "lsn";
        case TSVECTOROID: return "tsvector";
        case GTSVECTOROID: return "gtsvector";
        case TSQUERYOID: return "tsquery";
        case REGCONFIGOID: return "regconfig";
        case REGDICTIONARYOID: return "regdictionary";
        case JSONBOID: return "jsonb";
        case JSONPATHOID: return "jsonpath";
        case TXID_SNAPSHOTOID: return "txid_snapshot";
#if (PG_VERSION_NUM >= 130000)
        case PG_SNAPSHOTOID: return "pg_snapshot";
#endif
        case INT4RANGEOID: return "int4range";
        case NUMRANGEOID: return "numrange";
        case TSRANGEOID: return "tsrange";
        case TSTZRANGEOID: return "tstzrange";
        case DATERANGEOID: return "daterange";
        case INT8RANGEOID: return "int8range";
#if (PG_VERSION_NUM >= 140000)
        case INT4MULTIRANGEOID: return "int4multirange";
        case NUMMULTIRANGEOID: return "nummultirange";
        case TSMULTIRANGEOID: return "tsmultirange";
        case TSTZMULTIRANGEOID: return "tstzmultirange";
        case DATEMULTIRANGEOID: return "datemultirange";
        case INT8MULTIRANGEOID: return "int8multirange";
#endif
        case RECORDOID: return "record";
        case RECORDARRAYOID: return "recordarray";
        case CSTRINGOID: return "cstring";
        case ANYOID: return "any";
        case ANYARRAYOID: return "anyarray";
        case VOIDOID: return "void";
        case TRIGGEROID: return "trigger";
#if (PG_VERSION_NUM >= 140000)
        case EVENT_TRIGGEROID: return "event_trigger";
#else
        case EVTTRIGGEROID: return "evttrigger";
#endif
        case LANGUAGE_HANDLEROID: return "language_handler";
        case INTERNALOID: return "internal";
#if (PG_VERSION_NUM >= 130000)
#else
        case OPAQUEOID: return "opaque";
#endif
        case ANYELEMENTOID: return "anyelement";
        case ANYNONARRAYOID: return "anynonarray";
        case ANYENUMOID: return "anyenum";
        case FDW_HANDLEROID: return "fdw_handler";
        case INDEX_AM_HANDLEROID: return "index_am_handler";
        case TSM_HANDLEROID: return "tsm_handler";
        case TABLE_AM_HANDLEROID: return "table_am_handler";
        case ANYRANGEOID: return "anyrange";
#if (PG_VERSION_NUM >= 130000)
        case ANYCOMPATIBLEOID: return "anycompatible";
        case ANYCOMPATIBLEARRAYOID: return "anycompatiblearray";
        case ANYCOMPATIBLENONARRAYOID: return "anycompatiblenonarray";
        case ANYCOMPATIBLERANGEOID: return "anycompatiblerange";
#endif
#if (PG_VERSION_NUM >= 140000)
        case ANYMULTIRANGEOID: return "anymultirange";
        case ANYCOMPATIBLEMULTIRANGEOID: return "anycompatiblemultirange";
        case PG_BRIN_BLOOM_SUMMARYOID: return "pg_brin_bloom_summary";
        case PG_BRIN_MINMAX_MULTI_SUMMARYOID: return "pg_brin_minmax_multi_summary";
#endif
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
#if (PG_VERSION_NUM >= 140000)
        case PG_TYPEARRAYOID: return "pg_typearray";
        case PG_ATTRIBUTEARRAYOID: return "pg_attributearray";
        case PG_PROCARRAYOID: return "pg_procarray";
        case PG_CLASSARRAYOID: return "pg_classarray";
#endif
        case JSONARRAYOID: return "jsonarray";
        case XMLARRAYOID: return "xmlarray";
#if (PG_VERSION_NUM >= 130000)
        case XID8ARRAYOID: return "xid8array";
#endif
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
#if (PG_VERSION_NUM >= 130000)
        case REGCOLLATIONARRAYOID: return "regcollationarray";
#endif
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
#if (PG_VERSION_NUM >= 130000)
        case PG_SNAPSHOTARRAYOID: return "pg_snapshotarray";
#endif
        case INT4RANGEARRAYOID: return "int4rangearray";
        case NUMRANGEARRAYOID: return "numrangearray";
        case TSRANGEARRAYOID: return "tsrangearray";
        case TSTZRANGEARRAYOID: return "tstzrangearray";
        case DATERANGEARRAYOID: return "daterangearray";
        case INT8RANGEARRAYOID: return "int8rangearray";
#if (PG_VERSION_NUM >= 140000)
        case INT4MULTIRANGEARRAYOID: return "int4multirangearray";
        case NUMMULTIRANGEARRAYOID: return "nummultirangearray";
        case TSMULTIRANGEARRAYOID: return "tsmultirangearray";
        case TSTZMULTIRANGEARRAYOID: return "tstzmultirangearray";
        case DATEMULTIRANGEARRAYOID: return "datemultirangearray";
        case INT8MULTIRANGEARRAYOID: return "int8multirangearray";
#endif
        case CSTRINGARRAYOID: return "cstringarray";
        default: return NULL;
    }
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


static ngx_int_t ngx_postgres_output_plain_csv(ngx_postgres_save_t *s, ngx_str_t content_type) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    r->headers_out.content_type = content_type;
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    if (!PQntuples(s->res) || !PQnfields(s->res)) return NGX_OK;
    size_t size = 0;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[d->index];
    ngx_http_upstream_t *u = r->upstream;
    if (query->output.header && !u->out_bufs) {
        size += PQnfields(s->res) - 1; // header delimiters
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = ngx_strlen(PQfname(s->res, col));
            if (query->output.quote) size++;
            if (query->output.escape) size += ngx_postgres_count((u_char *)PQfname(s->res, col), len, query->output.escape);
            else size += len;
            if (location->append && !ngx_strstr(PQfname(s->res, col), "::")) {
                if (query->output.escape) size += ngx_postgres_count((u_char *)"::", sizeof("::") - 1, query->output.escape);
                else size += sizeof("::") - 1;
                Oid oid = PQftype(s->res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (query->output.escape) size += ngx_postgres_count((u_char *)type, ngx_strlen(type), query->output.escape);
                    else size += ngx_strlen(type);
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (query->output.escape) size += ngx_postgres_count((u_char *)type, len, query->output.escape);
                    else size += len;
                }
            }
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
    if (!b) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
    if (query->output.header && !u->out_bufs->next) {
        for (int col = 0; col < PQnfields(s->res); col++) {
            int len = ngx_strlen(PQfname(s->res, col));
            if (col > 0) *b->last++ = query->output.delimiter;
            if (query->output.quote) *b->last++ = query->output.quote;
            if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)PQfname(s->res, col), len, query->output.escape);
            else b->last = ngx_copy(b->last, PQfname(s->res, col), len);
            if (location->append && !ngx_strstr(PQfname(s->res, col), "::")) {
                if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)"::", sizeof("::") - 1, query->output.escape);
                else b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                Oid oid = PQftype(s->res, col);
                const char *type = PQftypeMy(oid);
                if (type) {
                    if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, ngx_strlen(type), query->output.escape);
                    else b->last = ngx_copy(b->last, type, ngx_strlen(type));
                } else {
                    size_t len = snprintf(NULL, 0, "%i", oid);
                    char type[len + 1];
                    snprintf(type, len + 1, "%i", oid);
                    if (query->output.escape) b->last = ngx_postgres_escape(b->last, (u_char *)type, len, query->output.escape);
                    else b->last = ngx_copy(b->last, type, len);
                }
            }
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
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
}


ngx_int_t ngx_postgres_output_plain(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_plain_csv(s, (ngx_str_t)ngx_string("text/plain"));
}


ngx_int_t ngx_postgres_output_csv(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    return ngx_postgres_output_plain_csv(s, (ngx_str_t)ngx_string("text/csv"));
}


ngx_int_t ngx_postgres_output_json(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    size_t size = 0;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
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
            if (location->append && !ngx_strstr(PQfname(s->res, col), "::")) {
                size += 2 * PQntuples(s->res);
                Oid oid = PQftype(s->res, col);
                const char *type = PQftypeMy(oid);
                if (type) size += ngx_strlen(type) * PQntuples(s->res); else size += snprintf(NULL, 0, "%i", oid) * PQntuples(s->res);
            }
        }
        size += PQntuples(s->res) * (PQnfields(s->res) - 1); /* col delimiters */
        size += PQntuples(s->res) - 1;                      /* row delimiters */
    }
    if (!size) return NGX_OK;
    ngx_buf_t *b = ngx_postgres_buffer(r, size);
    if (!b) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
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
                if (location->append && !ngx_strstr(PQfname(s->res, col), "::")) {
                    b->last = ngx_copy(b->last, "::", sizeof("::") - 1);
                    Oid oid = PQftype(s->res, col);
                    const char *type = PQftypeMy(oid);
                    if (type) b->last = ngx_copy(b->last, type, ngx_strlen(type)); else {
                        size_t len = snprintf(NULL, 0, "%i", oid);
                        char type[len + 1];
                        snprintf(type, len + 1, "%i", oid);
                        b->last = ngx_copy(b->last, type, len);
                    }
                }
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
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
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


static ngx_int_t ngx_postgres_output_rds(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_str_set(&r->headers_out.content_type, "application/x-resty-dbd-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
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
    if (!b) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_postgres_buffer"); return NGX_ERROR; }
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
    if (b->last != b->end) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "b->last != b->end"); return NGX_ERROR; }
    return NGX_OK;
}


char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (!location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[location->query.nelts - 1];
    if (query->output.handler) return "duplicate";
    ngx_str_t *args = cf->args->elts;
    static const struct {
        ngx_str_t name;
        unsigned binary:1;
        ngx_postgres_save_handler_pt handler;
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
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
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
        if (args[i].len > sizeof("append=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"append=", sizeof("append=") - 1)) {
            args[i].len = args[i].len - (sizeof("append=") - 1);
            args[i].data = &args[i].data[sizeof("append=") - 1];
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { location->append = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"append\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &args[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
