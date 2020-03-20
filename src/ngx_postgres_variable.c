#include "ngx_postgres_module.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


static ngx_int_t ngx_postgres_variable_nfields(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
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
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    v->not_found = 1;
    if (!pd || !pd->variables.elts) return NGX_OK;
    ngx_str_t *elts = pd->variables.elts;
    ngx_uint_t index = (ngx_uint_t)data;
    if (!elts[index].data) return NGX_OK;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = elts[index].len;
    v->data = elts[index].data;
    return NGX_OK;
}


typedef struct {
    ngx_int_t col;
    ngx_int_t row;
    ngx_str_t variable;
    ngx_uint_t index;
    ngx_uint_t required;
    u_char *name;
} ngx_postgres_variable_t;


ngx_int_t ngx_postgres_variable_error(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_result_t *result = &pd->result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location->queries.elts;
    result->sql = query[pd->query].sql;
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


ngx_int_t ngx_postgres_variable_output(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_result_t *result = &pd->result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location->queries.elts;
    result->sql = query[pd->query].sql;
    PGresult *res = result->res;
    const char *value;
    result->ntuples = PQntuples(res);
    result->nfields = PQnfields(res);
    switch (PQresultStatus(res)) {
        case PGRES_TUPLES_OK:
            result->sfields.len = snprintf(NULL, 0, "%li", result->nfields);
            if (!(result->sfields.data = ngx_pnalloc(r->pool, result->sfields.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            result->sfields.len = ngx_snprintf(result->sfields.data, result->sfields.len, "%li", result->nfields) - result->sfields.data;
            result->stuples.len = snprintf(NULL, 0, "%li", result->ntuples);
            if (!(result->stuples.data = ngx_pnalloc(r->pool, result->stuples.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            result->stuples.len = ngx_snprintf(result->stuples.data, result->stuples.len, "%li", result->nfields) - result->stuples.data;
            if ((value = PQcmdTuples(res)) && (result->cmdTuples.len = ngx_strlen(value))) {
                if (!(result->cmdTuples.data = ngx_pnalloc(r->pool, result->cmdTuples.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(result->cmdTuples.data, value, result->cmdTuples.len);
            } // fall through
        case PGRES_COMMAND_OK:
            if ((value = PQcmdStatus(res)) && (result->cmdStatus.len = ngx_strlen(value))) {
                if (!(result->cmdStatus.data = ngx_pnalloc(r->pool, result->cmdStatus.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(result->cmdStatus.data, value, result->cmdStatus.len);
            } // fall through
        default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res)); break;
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_variable_set(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location->queries.elts;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "query = %i", pd->query);
    ngx_array_t *variables = &query[pd->query].variables;
    if (!variables->elts) return NGX_OK;
    ngx_postgres_variable_t *variable = variables->elts;
    ngx_str_t *elts = pd->variables.elts;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nelts = %i", pd->variables.nelts);
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    result->ntuples = PQntuples(res);
    result->nfields = PQnfields(res);
    for (ngx_uint_t i = 0; i < variables->nelts; i++) {
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (variable[i].col == NGX_ERROR) {
            if ((variable[i].col = PQfnumber(res, (const char *)variable[i].name)) == -1) {
                if (variable[i].required) {
                    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value from col \"%s\" that wasn't found in the received result-set in location \"%V\"", &variable[i].variable, variable[i].name, &core_loc_conf->name);
                    return NGX_ERROR;
                }
                continue;
            }
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (variable[i].row >= result->ntuples || variable[i].col >= result->nfields) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires value out of range of the received result-set (rows:%i cols:%i) in location \"%V\"", &variable[i].variable, result->ntuples, result->nfields, &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (PQgetisnull(res, variable[i].row, variable[i].col)) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-NULL value in location \"%V\"", &variable[i].variable, &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(elts[variable[i].index].len = PQgetlength(res, variable[i].row, variable[i].col))) {
            if (variable[i].required) {
                ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"postgres_set\" for variable \"$%V\" requires non-zero length value in location \"%V\"", &variable[i].variable, &core_loc_conf->name);
                return NGX_ERROR;
            }
            continue;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        if (!(elts[variable[i].index].data = ngx_pnalloc(r->pool, elts[variable[i].index].len))) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc");
            return NGX_ERROR;
        }
//        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "row = %i, col = %i, name = %s, required = %s, index = %i", variable[i].row, variable[i].col, variable[i].name ? variable[i].name : (u_char *)"(null)", variable[i].required ? "true" : "false", variable[i].index);
        ngx_memcpy(elts[variable[i].index].data, PQgetvalue(res, variable[i].row, variable[i].col), elts[variable[i].index].len);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%V = %V", &variable[i].variable, &elts[variable[i].index]);
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
    ngx_postgres_location_t *location = conf;
    if (location->query == NGX_CONF_UNSET_PTR) return "must defined after \"postgres_query\" directive";
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len < 2) return "error: empty variable name";
    if (elts[1].data[0] != '$') return "error: invalid variable name";
    elts[1].len--;
    elts[1].data++;
    if (!elts[3].len) return "error: empty col";
    ngx_array_t *variables = &location->query->variables;
    if (!variables->elts && ngx_array_init(variables, cf->pool, 1, sizeof(ngx_postgres_variable_t)) != NGX_OK) return "error: !ngx_array_init != NGX_OK";
    ngx_postgres_variable_t *variable = ngx_array_push(variables);
    if (!variable) return "error: !ngx_array_push";
    variable->index = location->index++;
    variable->variable = elts[1];
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &variable->variable, NGX_HTTP_VAR_CHANGEABLE);
    if (!var) return "error: !ngx_http_add_variable";
    ngx_int_t index = ngx_http_get_variable_index(cf, &variable->variable);
    if (index == NGX_ERROR) return "error: ngx_http_get_variable_index == NGX_ERROR";
    var->index = (ngx_uint_t)index;
    var->get_handler = ngx_postgres_variable_get;
    var->data = (uintptr_t)variable->index;
    if ((variable->row = ngx_atoi(elts[2].data, elts[2].len)) == NGX_ERROR) return "error: invalid row number";
    if ((variable->col = ngx_atoi(elts[3].data, elts[3].len)) == NGX_ERROR) { /* get col by name */
        if (!(variable->name = ngx_pnalloc(cf->pool, elts[3].len + 1))) return "error: !ngx_pnalloc";
        (void) ngx_cpystrn(variable->name, elts[3].data, elts[3].len + 1);
    }
    if (cf->args->nelts == 4) variable->required = 0; else { /* user-specified value */
        ngx_conf_enum_t *e = ngx_postgres_requirement_options;
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[4].len && !ngx_strncasecmp(e[i].name.data, elts[4].data, elts[4].len)) { variable->required = e[i].value; break; }
        if (!e[i].name.len) return "invalid required";
    }
    return NGX_CONF_OK;
}
