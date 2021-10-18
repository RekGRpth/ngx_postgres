#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_variable_nfields(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.sfields.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.sfields.len;
    v->data = d->result.sfields.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_ntuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.stuples.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.stuples.len;
    v->data = d->result.stuples.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_cmdtuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.cmdTuples.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.cmdTuples.len;
    v->data = d->result.cmdTuples.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_cmdstatus(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.cmdStatus.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.cmdStatus.len;
    v->data = d->result.cmdStatus.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_query(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.sql.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.sql.len;
    v->data = d->result.sql.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_error(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d) return NGX_OK;
    if (!d->result.error.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = d->result.error.len;
    v->data = d->result.error.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *d = u->peer.data;
    if (!d || !d->variable.nelts) return NGX_OK;
    ngx_str_t *variableelts = d->variable.elts;
    ngx_uint_t index = (ngx_uint_t)data;
    if (!variableelts[index].data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = variableelts[index].len;
    v->data = variableelts[index].data;
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_output(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[d->query];
    d->result.sql = query->sql;
    const char *value;
    d->result.ntuples = d->result.nsingle ? d->result.nsingle : PQntuples(s->res);
    d->result.nfields = PQnfields(s->res);
    switch (PQresultStatus(s->res)) {
        case PGRES_TUPLES_OK:
            d->result.sfields.len = snprintf(NULL, 0, "%i", d->result.nfields);
            if (!(d->result.sfields.data = ngx_pnalloc(r->pool, d->result.sfields.len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            d->result.sfields.len = ngx_snprintf(d->result.sfields.data, d->result.sfields.len, "%i", d->result.nfields) - d->result.sfields.data;
            d->result.stuples.len = snprintf(NULL, 0, "%i", d->result.ntuples);
            if (!(d->result.stuples.data = ngx_pnalloc(r->pool, d->result.stuples.len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            d->result.stuples.len = ngx_snprintf(d->result.stuples.data, d->result.stuples.len, "%i", d->result.ntuples) - d->result.stuples.data;
            // fall through
        case PGRES_COMMAND_OK:
            if (ngx_strncasecmp((u_char *)PQcmdStatus(s->res), (u_char *)"SELECT", sizeof("SELECT") - 1) && (value = PQcmdTuples(s->res)) && (d->result.cmdTuples.len = ngx_strlen(value))) {
                if (!(d->result.cmdTuples.data = ngx_pnalloc(r->pool, d->result.cmdTuples.len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(d->result.cmdTuples.data, value, d->result.cmdTuples.len);
            }
            if ((value = PQcmdStatus(s->res)) && (d->result.cmdStatus.len = ngx_strlen(value))) {
                if (!(d->result.cmdStatus.data = ngx_pnalloc(r->pool, d->result.cmdStatus.len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(d->result.cmdStatus.data, value, d->result.cmdStatus.len);
            } // fall through
        default:
            if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(s->res)), value); }
            else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, PQresStatus(PQresultStatus(s->res))); }
            break;
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_set(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "query = %i", d->query);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[d->query];
    if (!query->variable.nelts) return NGX_OK;
    ngx_postgres_variable_t *variable = query->variable.elts;
    ngx_str_t *variableelts = d->variable.elts;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "nelts = %i", d->variable.nelts);
    d->result.ntuples = PQntuples(s->res);
    d->result.nfields = PQnfields(s->res);
    const char *value;
    for (ngx_uint_t i = 0; i < query->variable.nelts; i++) if (variable[i].type) {
        switch (PQresultStatus(s->res)) {
            case PGRES_TUPLES_OK:
                switch (variable[i].type) {
                    case type_nfields:
                        variableelts[variable[i].index].len = snprintf(NULL, 0, "%i", d->result.nfields);
                        if (!(variableelts[variable[i].index].data = ngx_pnalloc(r->pool, variableelts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        variableelts[variable[i].index].len = ngx_snprintf(variableelts[variable[i].index].data, variableelts[variable[i].index].len, "%i", d->result.nfields) - variableelts[variable[i].index].data;
                        break;
                    case type_ntuples:
                        variableelts[variable[i].index].len = snprintf(NULL, 0, "%i", d->result.ntuples);
                        if (!(variableelts[variable[i].index].data = ngx_pnalloc(r->pool, variableelts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        variableelts[variable[i].index].len = ngx_snprintf(variableelts[variable[i].index].data, variableelts[variable[i].index].len, "%i", d->result.ntuples) - variableelts[variable[i].index].data;
                        break;
                    case type_cmdTuples:
                        if ((value = PQcmdTuples(s->res)) && (variableelts[variable[i].index].len = ngx_strlen(value))) {
                            if (!(variableelts[variable[i].index].data = ngx_pnalloc(r->pool, variableelts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                            ngx_memcpy(variableelts[variable[i].index].data, value, variableelts[variable[i].index].len);
                        }
                        break;
                    default: break;
                } // fall through
            case PGRES_COMMAND_OK:
                switch (variable[i].type) {
                    case type_cmdStatus:
                        if ((value = PQcmdStatus(s->res)) && (variableelts[variable[i].index].len = ngx_strlen(value))) {
                            if (!(variableelts[variable[i].index].data = ngx_pnalloc(r->pool, variableelts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                            ngx_memcpy(variableelts[variable[i].index].data, value, variableelts[variable[i].index].len);
                        }
                        break;
                    default: break;
                } // fall through
            default:
                if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(s->res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, PQresStatus(PQresultStatus(s->res))); }
                break;
        }
    } else if (variable[i].handler) {
        ngx_http_upstream_t *u = r->upstream;
        ngx_chain_t *chain = u->out_bufs;
        u->out_bufs = NULL;
        if (variable[i].handler(s) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!handler"); return NGX_ERROR; }
        variableelts[variable[i].index].len = u->out_bufs->buf->end - u->out_bufs->buf->start;
        variableelts[variable[i].index].data = u->out_bufs->buf->start;
        u->out_bufs = chain;
    } else {
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (variable[i].field) {
            ngx_int_t n = PQfnumber(s->res, (const char *)variable[i].field);
            if (n >= 0) variable[i].col = (ngx_uint_t)n; else {
                if (variable[i].required) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value from col \"%s\" that wasn't found in the received result-set in location \"%V\"", &variable[i].name, variable[i].field, &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
                continue;
            }
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (variable[i].row >= d->result.ntuples || variable[i].col >= d->result.nfields) {
            if (variable[i].required) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value out of range of the received result-set (rows:%i cols:%i) in location \"%V\"", &variable[i].name, d->result.ntuples, d->result.nfields, &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (PQgetisnull(s->res, variable[i].row, variable[i].col)) {
            if (variable[i].required) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-NULL value in location \"%V\"", &variable[i].name, &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(variableelts[variable[i].index].len = PQgetlength(s->res, variable[i].row, variable[i].col))) {
            if (variable[i].required) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-zero length value in location \"%V\"", &variable[i].name, &core->name); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(variableelts[variable[i].index].data = ngx_pnalloc(r->pool, variableelts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        ngx_memcpy(variableelts[variable[i].index].data, PQgetvalue(s->res, variable[i].row, variable[i].col), variableelts[variable[i].index].len);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%V = %V", &variable[i].name, &variableelts[variable[i].index]);
    }
    return NGX_OK;
}


static ngx_http_variable_t ngx_postgres_module_variable[] = {
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
  { .name = ngx_string("postgres_cmdstatus"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_cmdstatus,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
  { .name = ngx_string("postgres_query"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_query,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
  { .name = ngx_string("postgres_error"),
    .set_handler = NULL,
    .get_handler = ngx_postgres_variable_error,
    .data = 0,
    .flags = NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH,
    .index = 0 },
    ngx_http_null_variable
};


ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_postgres_module_variable; v->name.len; v++) {
        ngx_http_variable_t *variable = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!variable) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_http_add_variable"); return NGX_ERROR; }
        variable->get_handler = v->get_handler;
        variable->data = v->data;
    }
    return NGX_OK;
}


char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (!location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[location->query.nelts - 1];
    ngx_str_t *args = cf->args->elts;
    if (args[1].len < 2) return "error: empty variable name";
    if (args[1].data[0] != '$') return "error: invalid variable name";
    args[1].len--;
    args[1].data++;
    ngx_postgres_variable_t *variable = ngx_array_push(&query->variable);
    if (!variable) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(variable, sizeof(*variable));
    variable->index = location->variable++;
    variable->name = args[1];
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &variable->name, NGX_HTTP_VAR_CHANGEABLE);
    if (!var) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_http_add_variable", &cmd->name); return NGX_CONF_ERROR; }
    ngx_int_t index = ngx_http_get_variable_index(cf, &variable->name);
    if (index == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_http_get_variable_index == NGX_ERROR", &cmd->name); return NGX_CONF_ERROR; }
    var->index = (ngx_uint_t)index;
    var->get_handler = ngx_postgres_variable_get;
    var->data = (uintptr_t)variable->index;
    if (cf->args->nelts == 3) {
        static const struct {
            ngx_str_t name;
            ngx_postgres_variable_type_t type;
            ngx_postgres_save_handler_pt handler;
        } e[] = {
            { ngx_string("ntuples"), type_ntuples, NULL },
            { ngx_string("nfields"), type_nfields, NULL },
            { ngx_string("cmdTuples"), type_cmdTuples, NULL },
            { ngx_string("cmdStatus"), type_cmdStatus, NULL },
            { ngx_string("value"), 0, ngx_postgres_output_value },
            { ngx_string("json"), 0, ngx_postgres_output_json },
            { ngx_null_string, 0, NULL }
        };
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == args[2].len && !ngx_strncmp(e[i].name.data, args[2].data, args[2].len)) { variable->type = e[i].type; variable->handler = e[i].handler; break; }
        if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: type \"%V\" must be \"nfields\", \"ntuples\", \"cmdTuples\", \"cmdStatus\", \"value\" or \"json\"", &cmd->name, &args[2]); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    }
    if (!args[3].len) return "error: empty col";
    ngx_int_t n = ngx_atoi(args[2].data, args[2].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: row \"%V\" must be number", &cmd->name, &args[2]); return NGX_CONF_ERROR; }
    variable->row = (ngx_uint_t)n;
    if ((n = ngx_atoi(args[3].data, args[3].len)) != NGX_ERROR) variable->col = (ngx_uint_t)n; else { /* get col by name */
        if (!(variable->field = ngx_pnalloc(cf->pool, args[3].len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(variable->field, args[3].data, args[3].len + 1);
    }
    if (cf->args->nelts == 4) variable->required = 0; else { /* user-specified value */
        static const ngx_conf_enum_t e[] = {
            { ngx_string("optional"), 0 },
            { ngx_string("required"), 1 },
            { ngx_null_string, 0 }
        };
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == args[4].len && !ngx_strncmp(e[i].name.data, args[4].data, args[4].len)) { variable->required = e[i].value; break; }
        if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: requirment \"%V\" must be \"optional\" or \"required\"", &cmd->name, &args[4]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}
