#include "ngx_postgres_include.h"


typedef ngx_int_t (*ngx_postgres_rewrite_handler_pt) (ngx_postgres_data_t *pd, ngx_uint_t key, ngx_uint_t status);


typedef struct  {
//    ngx_flag_t keep;
    ngx_postgres_rewrite_handler_pt handler;
    ngx_uint_t key;
    ngx_uint_t status;
} ngx_postgres_rewrite_t;


ngx_int_t ngx_postgres_rewrite_set(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "query = %i", pd->query.index);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[pd->query.index];
    ngx_array_t *array = &query->rewrite;
    if (!array->elts) return NGX_DONE;
    ngx_postgres_rewrite_t *rewrite = array->elts;
    ngx_int_t rc = NGX_DONE;
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    result->ntuples = PQntuples(res);
    result->nfields = PQnfields(res);
    if (ngx_strncasecmp((u_char *)PQcmdStatus(res), (u_char *)"SELECT", sizeof("SELECT") - 1)) {
        char *affected = PQcmdTuples(res);
        size_t affected_len = ngx_strlen(affected);
        if (affected_len) result->ncmdTuples = ngx_atoi((u_char *)affected, affected_len);
    }
    for (ngx_uint_t i = 0; i < array->nelts; i++) if ((rc = rewrite[i].handler(pd, rewrite[i].key, rewrite[i].status)) != NGX_DONE) { result->status = rc; break; }
    return rc;
}


static ngx_int_t ngx_postgres_rewrite_changes(ngx_postgres_data_t *pd, ngx_uint_t key, ngx_uint_t status) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    if (key % 2 == 0 && !result->ncmdTuples) return status;
    if (key % 2 == 1 && result->ncmdTuples > 0) return status;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_rewrite_rows(ngx_postgres_data_t *pd, ngx_uint_t key, ngx_uint_t status) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_result_t *result = &pd->result;
    PGresult *res = result->res;
    if (key % 2 == 0 && !result->ntuples) return status;
    if (key % 2 == 1 && result->ntuples > 0) return status;
    return NGX_DONE;
}


char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (!location->query.elts || !location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[location->query.nelts - 1];
    ngx_str_t *elts = cf->args->elts;
    ngx_str_t what = elts[1];
    ngx_str_t to = elts[2];
    static const struct {
        ngx_str_t name;
        ngx_uint_t key;
        ngx_postgres_rewrite_handler_pt handler;
    } e[] = {
        { ngx_string("no_changes"), 0, ngx_postgres_rewrite_changes },
        { ngx_string("changes"), 1, ngx_postgres_rewrite_changes },
        { ngx_string("no_rows"), 2, ngx_postgres_rewrite_rows },
        { ngx_string("rows"), 3, ngx_postgres_rewrite_rows },
/*        { ngx_string("no_errors"), 4, ngx_postgres_rewrite_valid },
        { ngx_string("errors"), 5, ngx_postgres_rewrite_valid },*/
        { ngx_null_string, 0, NULL }
    };
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == what.len && !ngx_strncasecmp(e[i].name.data, what.data, e[i].name.len)) break;
    if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: condition \"%V\" must be \"no_changes\", \"changes\", \"no_rows\", \"rows\", \"no_errors\" or \"errors\"", &cmd->name, &what); return NGX_CONF_ERROR; }
    ngx_array_t *array = &query->rewrite;
    if (!array->elts && ngx_array_init(array, cf->pool, 1, sizeof(ngx_postgres_rewrite_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_rewrite_t *rewrite = ngx_array_push(array);
    if (!rewrite) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(rewrite, sizeof(*rewrite));
    rewrite->handler = e[i].handler;
    rewrite->key = e[i].key;
/*    if (to.data[0] == '=') {
        rewrite->keep = 1;
        to.len--;
        to.data++;
    }*/
    ngx_int_t n = ngx_atoi(to.data, to.len);
    if (n == NGX_ERROR || n < NGX_HTTP_OK || n > NGX_HTTP_INSUFFICIENT_STORAGE || (n >= NGX_HTTP_SPECIAL_RESPONSE && n < NGX_HTTP_BAD_REQUEST)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid status value \"%V\" for condition \"%V\"", &cmd->name, &to, &what); return NGX_CONF_ERROR; }
    else rewrite->status = (ngx_uint_t)n;
    return NGX_CONF_OK;
}
