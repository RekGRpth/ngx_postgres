#include "ngx_postgres_include.h"


ngx_int_t ngx_postgres_rewrite_set(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "query = %i", d->query);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[d->query];
    ngx_array_t *rewrite = &query->rewrite;
    if (!rewrite->elts) return NGX_OK;
    ngx_postgres_rewrite_t *rewriteelts = rewrite->elts;
    ngx_int_t rc = NGX_OK;
    for (ngx_uint_t i = 0; i < rewrite->nelts; i++) if ((!rewriteelts[i].method || rewriteelts[i].method & r->method) && (rc = rewriteelts[i].handler(s, rewriteelts[i].key, rewriteelts[i].status)) != NGX_OK) {
        r->err_status = rc;
        if (rewriteelts[i].keep) rc = NGX_OK;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "rc = %i", rc);
        break;
    }
    return rc;
}


static ngx_int_t ngx_postgres_rewrite_changes(ngx_postgres_save_t *s, ngx_uint_t key, ngx_uint_t status) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (ngx_strncasecmp((u_char *)PQcmdStatus(s->res), (u_char *)"SELECT", sizeof("SELECT") - 1)) {
        char *affected = PQcmdTuples(s->res);
        size_t affected_len = ngx_strlen(affected);
        ngx_int_t ncmdTuples = NGX_ERROR;
        if (affected_len) ncmdTuples = ngx_atoi((u_char *)affected, affected_len);
        if (key % 2 == 0 && !ncmdTuples) return status;
        if (key % 2 == 1 && ncmdTuples > 0) return status;
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_rewrite_rows(ngx_postgres_save_t *s, ngx_uint_t key, ngx_uint_t status) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (key % 2 == 0 && !PQntuples(s->res)) return status;
    if (key % 2 == 1 && PQntuples(s->res) > 0) return status;
    return NGX_OK;
}


char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (!location->query.nelts) return "must defined after \"postgres_query\" directive";
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[location->query.nelts - 1];
    ngx_str_t *args = cf->args->elts;
    ngx_str_t what = args[cf->args->nelts - 2];
    ngx_str_t to = args[cf->args->nelts - 1];
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
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == what.len && !ngx_strncmp(e[i].name.data, what.data, e[i].name.len)) break;
    if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: condition \"%V\" must be \"no_changes\", \"changes\", \"no_rows\", \"rows\", \"no_errors\" or \"errors\"", &cmd->name, &what); return NGX_CONF_ERROR; }
    ngx_postgres_rewrite_t *rewrite = ngx_array_push(&query->rewrite);
    if (!rewrite) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(rewrite, sizeof(*rewrite));
    rewrite->handler = e[i].handler;
    rewrite->key = e[i].key;
    if (to.data[0] == '=') {
        rewrite->keep = 1;
        to.len--;
        to.data++;
    }
    ngx_int_t n = ngx_atoi(to.data, to.len);
    if (n == NGX_ERROR || n < NGX_HTTP_OK || n > NGX_HTTP_INSUFFICIENT_STORAGE || (n >= NGX_HTTP_SPECIAL_RESPONSE && n < NGX_HTTP_BAD_REQUEST)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid status value \"%V\" for condition \"%V\"", &cmd->name, &to, &what); return NGX_CONF_ERROR; }
    else rewrite->status = (ngx_uint_t)n;
    static const ngx_conf_bitmask_t b[] = {
        { ngx_string("UNKNOWN"), NGX_HTTP_UNKNOWN },
        { ngx_string("GET"), NGX_HTTP_GET },
        { ngx_string("HEAD"), NGX_HTTP_HEAD },
        { ngx_string("POST"), NGX_HTTP_POST },
        { ngx_string("PUT"), NGX_HTTP_PUT },
        { ngx_string("DELETE"), NGX_HTTP_DELETE },
        { ngx_string("MKCOL"), NGX_HTTP_MKCOL },
        { ngx_string("COPY"), NGX_HTTP_COPY },
        { ngx_string("MOVE"), NGX_HTTP_MOVE },
        { ngx_string("OPTIONS"), NGX_HTTP_OPTIONS },
        { ngx_string("PROPFIND"), NGX_HTTP_PROPFIND },
        { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
        { ngx_string("LOCK"), NGX_HTTP_LOCK },
        { ngx_string("UNLOCK"), NGX_HTTP_UNLOCK },
        { ngx_string("PATCH"), NGX_HTTP_PATCH },
        { ngx_string("TRACE"), NGX_HTTP_TRACE },
        { ngx_null_string, 0 }
    };
    for (ngx_uint_t j = 1; j < cf->args->nelts - 2; j++) for (ngx_uint_t i = 0; b[i].name.len; i++) if (b[i].name.len == args[j].len && !ngx_strncasecmp(b[i].name.data, args[j].data, b[i].name.len)) rewrite->method |= b[i].mask;
    return NGX_CONF_OK;
}
