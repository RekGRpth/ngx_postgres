#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_variable_nfields(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->sfields.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->sfields.len;
    v->data = result->sfields.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_ntuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->stuples.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->stuples.len;
    v->data = result->stuples.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_cmdtuples(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->cmdTuples.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->cmdTuples.len;
    v->data = result->cmdTuples.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_cmdstatus(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->cmdStatus.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->cmdStatus.len;
    v->data = result->cmdStatus.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_query(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->sql.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->sql.len;
    v->data = result->sql.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_error_(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd) return NGX_OK;
    ngx_postgres_result_t *result = &pd->result;
    if (!result->error.data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = result->error.len;
    v->data = result->error.data;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_variable_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->upstream) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "there is not upstream"); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    v->not_found = 1;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd || !pd->variable.elts) return NGX_OK;
    ngx_str_t *elts = pd->variable.elts;
    ngx_uint_t index = (ngx_uint_t)data;
    if (!elts[index].data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = elts[index].len;
    v->data = elts[index].data;
    return NGX_OK;
}


typedef enum {
    type_nfields = 1,
    type_ntuples,
    type_cmdTuples,
    type_cmdStatus,
} ngx_postgres_type_t;


typedef struct {
    ngx_postgres_handler_pt handler;
    ngx_postgres_type_t type;
    ngx_str_t name;
    ngx_uint_t col;
    ngx_uint_t index;
    ngx_uint_t required;
    ngx_uint_t row;
    u_char *field;
} ngx_postgres_variable_t;


ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_result_t *result = &pd->result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[pd->query.index];
    result->sql = query->sql;
    PGresult *res = result->res;
    result->ntuples = 0;
    result->nfields = 0;
    if (result->stuples.data) ngx_pfree(r->pool, result->stuples.data);
    if (result->sfields.data) ngx_pfree(r->pool, result->sfields.data);
    if (result->cmdTuples.data) ngx_pfree(r->pool, result->cmdTuples.data);
    if (result->cmdStatus.data) ngx_pfree(r->pool, result->cmdStatus.data);
    ngx_str_null(&result->stuples);
    ngx_str_null(&result->sfields);
    ngx_str_null(&result->cmdTuples);
    ngx_str_null(&result->cmdStatus);
    const char *value;
    if ((value = PQresultErrorMessage(res)) && !result->error.len && (result->error.len = ngx_strlen(value))) {
        if (!(result->error.data = ngx_pnalloc(r->pool, result->error.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        ngx_memcpy(result->error.data, value, result->error.len);
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_output(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_result_t *result = &pd->result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[pd->query.index];
    result->sql = query->sql;
    PGresult *res = result->res;
    const char *value;
    result->ntuples = result->nsingle ? result->nsingle : PQntuples(res);
    result->nfields = PQnfields(res);
    switch (PQresultStatus(res)) {
        case PGRES_TUPLES_OK:
            result->sfields.len = snprintf(NULL, 0, "%li", result->nfields);
            if (!(result->sfields.data = ngx_pnalloc(r->pool, result->sfields.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            result->sfields.len = ngx_snprintf(result->sfields.data, result->sfields.len, "%li", result->nfields) - result->sfields.data;
            result->stuples.len = snprintf(NULL, 0, "%li", result->ntuples);
            if (!(result->stuples.data = ngx_pnalloc(r->pool, result->stuples.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            result->stuples.len = ngx_snprintf(result->stuples.data, result->stuples.len, "%li", result->ntuples) - result->stuples.data;
            if ((value = PQcmdTuples(res)) && (result->cmdTuples.len = ngx_strlen(value))) {
                if (!(result->cmdTuples.data = ngx_pnalloc(r->pool, result->cmdTuples.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(result->cmdTuples.data, value, result->cmdTuples.len);
            } // fall through
        case PGRES_COMMAND_OK:
            if ((value = PQcmdStatus(res)) && (result->cmdStatus.len = ngx_strlen(value))) {
                if (!(result->cmdStatus.data = ngx_pnalloc(r->pool, result->cmdStatus.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(result->cmdStatus.data, value, result->cmdStatus.len);
            } // fall through
        default:
            if ((value = PQcmdStatus(res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(res)), value); }
            else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(res))); }
            break;
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_set(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "query = %i", pd->query.index);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[pd->query.index];
    ngx_array_t *array = &query->variable;
    if (!array->elts) return NGX_OK;
    ngx_postgres_variable_t *variable = array->elts;
    ngx_str_t *elts = pd->variable.elts;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nelts = %i", pd->variable.nelts);
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    result->ntuples = PQntuples(res);
    result->nfields = PQnfields(res);
    const char *value;
    for (ngx_uint_t i = 0; i < array->nelts; i++) if (variable[i].type) {
        switch (PQresultStatus(res)) {
            case PGRES_TUPLES_OK:
                switch (variable[i].type) {
                    case type_nfields:
                        elts[variable[i].index].len = snprintf(NULL, 0, "%li", result->nfields);
                        if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        elts[variable[i].index].len = ngx_snprintf(elts[variable[i].index].data, elts[variable[i].index].len, "%li", result->nfields) - elts[variable[i].index].data;
                        break;
                    case type_ntuples:
                        elts[variable[i].index].len = snprintf(NULL, 0, "%li", result->ntuples);
                        if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        elts[variable[i].index].len = ngx_snprintf(elts[variable[i].index].data, elts[variable[i].index].len, "%li", result->ntuples) - elts[variable[i].index].data;
                        break;
                    case type_cmdTuples:
                        if ((value = PQcmdTuples(res)) && (elts[variable[i].index].len = ngx_strlen(value))) {
                            if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                            ngx_memcpy(elts[variable[i].index].data, value, elts[variable[i].index].len);
                        }
                        break;
                    default: break;
                } // fall through
            case PGRES_COMMAND_OK:
                switch (variable[i].type) {
                    case type_cmdStatus:
                        if ((value = PQcmdStatus(res)) && (elts[variable[i].index].len = ngx_strlen(value))) {
                            if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                            ngx_memcpy(elts[variable[i].index].data, value, elts[variable[i].index].len);
                        }
                        break;
                    default: break;
                } // fall through
            default:
                if ((value = PQcmdStatus(res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(res))); }
                break;
        }
    } else if (variable[i].handler) {
        ngx_http_upstream_t *u = r->upstream;
        ngx_chain_t *chain = u->out_bufs;
        u->out_bufs = NULL;
        if (variable[i].handler(pd) != NGX_DONE) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!handler"); return NGX_ERROR; }
        elts[variable[i].index].len = u->out_bufs->buf->end - u->out_bufs->buf->start;
        elts[variable[i].index].data = u->out_bufs->buf->start;
        u->out_bufs = chain;
    } else {
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (variable[i].field) {
            ngx_int_t n = PQfnumber(res, (const char *)variable[i].field);
            if (n >= 0) variable[i].col = (ngx_uint_t)n; else {
                if (variable[i].required) {
                    ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value from col \"%s\" that wasn't found in the received result-set in location \"%V\"", &variable[i].name, variable[i].field, &core->name);
                    return NGX_ERROR;
                }
                continue;
            }
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (variable[i].row >= result->ntuples || variable[i].col >= result->nfields) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value out of range of the received result-set (rows:%i cols:%i) in location \"%V\"", &variable[i].name, result->ntuples, result->nfields, &core->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (PQgetisnull(res, variable[i].row, variable[i].col)) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-NULL value in location \"%V\"", &variable[i].name, &core->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(elts[variable[i].index].len = PQgetlength(res, variable[i].row, variable[i].col))) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-zero length value in location \"%V\"", &variable[i].name, &core->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc");
            return NGX_ERROR;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, field = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].field ? variable[i].field : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        ngx_memcpy(elts[variable[i].index].data, PQgetvalue(res, variable[i].row, variable[i].col), elts[variable[i].index].len);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%V = %V", &variable[i].name, &elts[variable[i].index]);
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
    .get_handler = ngx_postgres_variable_error_,
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
    if (!location->query.elts || !location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[location->query.nelts - 1];
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len < 2) return "error: empty variable name";
    if (elts[1].data[0] != '$') return "error: invalid variable name";
    elts[1].len--;
    elts[1].data++;
    ngx_array_t *array = &query->variable;
    if (!array->elts && ngx_array_init(array, cf->pool, 1, sizeof(ngx_postgres_variable_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_variable_t *variable = ngx_array_push(array);
    if (!variable) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(variable, sizeof(*variable));
    variable->index = location->variable++;
    variable->name = elts[1];
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
            ngx_postgres_type_t type;
            ngx_postgres_handler_pt handler;
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
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[2].len && !ngx_strncasecmp(e[i].name.data, elts[2].data, elts[2].len)) { variable->type = e[i].type; variable->handler = e[i].handler; break; }
        if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: type \"%V\" must be \"nfields\", \"ntuples\", \"cmdTuples\", \"cmdStatus\", \"value\" or \"json\"", &cmd->name, &elts[2]); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    }
    if (!elts[3].len) return "error: empty col";
    ngx_int_t n = ngx_atoi(elts[2].data, elts[2].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: row \"%V\" must be number", &cmd->name, &elts[2]); return NGX_CONF_ERROR; }
    variable->row = (ngx_uint_t)n;
    if ((n = ngx_atoi(elts[3].data, elts[3].len)) != NGX_ERROR) variable->col = (ngx_uint_t)n; else { /* get col by name */
        if (!(variable->field = ngx_pnalloc(cf->pool, elts[3].len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(variable->field, elts[3].data, elts[3].len + 1);
    }
    if (cf->args->nelts == 4) variable->required = 0; else { /* user-specified value */
        static const ngx_conf_enum_t e[] = {
            { ngx_string("optional"), 0 },
            { ngx_string("required"), 1 },
            { ngx_null_string, 0 }
        };
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[4].len && !ngx_strncasecmp(e[i].name.data, elts[4].data, elts[4].len)) { variable->required = e[i].value; break; }
        if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: requirment \"%V\" must be \"optional\" or \"required\"", &cmd->name, &elts[4]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}
