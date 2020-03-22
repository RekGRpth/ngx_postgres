#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static void ngx_postgres_event_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_data_t *pd = c->data;
    ngx_http_request_t *r = pd->request;
    ngx_http_upstream_t *u = r->upstream;
    if (c->read->timedout) return ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    if (c->write->timedout) return ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    if (ngx_http_upstream_test_connect(c) != NGX_OK) return ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
    ngx_postgres_process_events(r);
//    ngx_http_run_posted_requests(c);
}


static ngx_int_t ngx_postgres_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->complex.value.data) { // use complex value
        ngx_str_t host;
        if (ngx_http_complex_value(r, &location->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        if (!host.len) {
            ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"postgres_pass\" (was: \"%V\") in location \"%V\"", &location->complex.value, &core->name);
            return NGX_ERROR;
        }
        if (!(u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        u->resolved->host = host;
        u->resolved->no_port = 1;
    }
    ngx_str_set(&u->schema, "postgres://");
    u->output.tag = (ngx_buf_tag_t)&ngx_postgres_module;
    u->request_sent = 1;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_connection_t *c = pdc->pc.connection;
    c->data = pd;
    c->read->handler = ngx_postgres_event_handler;
    c->write->handler = ngx_postgres_event_handler;
    if (pdc->state != state_db_connect) {
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
    }
    return NGX_OK;
}



static void ngx_postgres_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    if (rc == NGX_OK) ngx_postgres_output_chain(r);
}


ngx_int_t ngx_postgres_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (r->subrequest_in_memory) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "subrequest_in_memory"); return NGX_HTTP_INTERNAL_SERVER_ERROR; } // TODO: add support for subrequest in memory by emitting output into u->buffer instead
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (!location->queries.elts) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "missing \"postgres_query\" in location \"%V\"", &core->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &location->conf;
    u->create_request = ngx_postgres_create_request;
    u->reinit_request = ngx_postgres_reinit_request;
    u->finalize_request = ngx_postgres_finalize_request;
    r->main->count++;
    ngx_http_upstream_init(r);
    return NGX_DONE;
}
