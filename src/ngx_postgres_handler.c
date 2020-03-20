#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static void ngx_postgres_write_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    ngx_peer_connection_t *pc = &u->peer;
    ngx_connection_t *c = pc->connection;
    if (c->write->timedout) return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    if (ngx_http_upstream_test_connect(c) != NGX_OK) return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
    ngx_postgres_process_events(r);
}


static void ngx_postgres_read_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    ngx_peer_connection_t *pc = &u->peer;
    ngx_connection_t *c = pc->connection;
    if (c->read->timedout) return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    if (ngx_http_upstream_test_connect(c) != NGX_OK) return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
    ngx_postgres_process_events(r);
}


static ngx_int_t ngx_postgres_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->request_bufs = NULL;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    /* override the read/write event handler to our own */
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    if (!pd->read) pd->read = u->read_event_handler;
    if (!pd->write) pd->write = u->write_event_handler;
    u->read_event_handler = ngx_postgres_read_event_handler;
    u->write_event_handler = ngx_postgres_write_event_handler;
    return NGX_OK;
}


static void ngx_postgres_abort_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}


static void ngx_postgres_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    if (rc == NGX_OK) ngx_postgres_output_chain(r);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    if (pd->read) u->read_event_handler = pd->read;
    if (pd->write) u->write_event_handler = pd->write;
}


static ngx_int_t ngx_postgres_process_header(ngx_http_request_t *r) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "should not be called by the upstream");
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_input_filter_init(void *data) {
    ngx_http_request_t *r = data;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "should not be called by the upstream");
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "should not be called by the upstream");
    return NGX_ERROR;
}


ngx_http_upstream_srv_conf_t *ngx_postgres_find_upstream(ngx_http_request_t *r, ngx_url_t *url) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    ngx_http_upstream_srv_conf_t *elts = conf->upstreams.elts;
    for (ngx_uint_t i = 0; i < conf->upstreams.nelts; i++) if (elts[i].host.len == url->host.len && !ngx_strncasecmp(elts[i].host.data, url->host.data, url->host.len)) return &elts[i];
    return NULL;
}


ngx_int_t ngx_postgres_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (r->subrequest_in_memory) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "r->subrequest_in_memory"); return NGX_HTTP_INTERNAL_SERVER_ERROR; } /* TODO: add support for subrequest in memory by emitting output into u->buffer instead */
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (!location->queries.elts) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "missing \"postgres_query\" in location \"%V\"", &core->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (location->complex.value.data) { /* use complex value */
        ngx_str_t host;
        if (ngx_http_complex_value(r, &location->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        if (!host.len) {
            ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"postgres_pass\" (was: \"%V\") in location \"%V\"", &location->complex.value, &core->name);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.host = host;
        url.no_resolve = 1;
        if (!(location->upstream.upstream = ngx_postgres_find_upstream(r, &url))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream name \"%V\" not found", &host); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    }
    ngx_http_upstream_t *u = r->upstream;
    u->schema.len = sizeof("postgres://") - 1;
    u->schema.data = (u_char *) "postgres://";
    u->output.tag = (ngx_buf_tag_t) &ngx_postgres_module;
    u->conf = &location->upstream;
    u->create_request = ngx_postgres_create_request;
    u->reinit_request = ngx_postgres_reinit_request;
    u->process_header = ngx_postgres_process_header;
    u->abort_request = ngx_postgres_abort_request;
    u->finalize_request = ngx_postgres_finalize_request;
    /* we bypass the upstream input filter mechanism in ngx_http_upstream_process_headers */
    u->input_filter_init = ngx_postgres_input_filter_init;
    u->input_filter = ngx_postgres_input_filter;
    u->input_filter_ctx = NULL;
    r->main->count++;
    ngx_http_upstream_init(r);
    /* override the read/write event handler to our own */
    if (u->reinit_request(r) != NGX_OK) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "reinit_request != NGX_OK"); }
//    u->write_event_handler = ngx_postgres_write_event_handler;
//    u->read_event_handler = ngx_postgres_read_event_handler;
    /* a bit hack-ish way to return error response (clean-up part) */
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "r->main->count = %i", r->main->count);
    /*if (u->peer.connection && !u->peer.connection->fd) {
        if (u->peer.connection->write->timer_set) ngx_del_timer(u->peer.connection->write);
        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
            u->peer.connection->pool = NULL;
        }
        ngx_free_connection(u->peer.connection);
        u->peer.connection = NULL;
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_SERVICE_UNAVAILABLE);
    }*/
    return NGX_DONE;
}


void ngx_postgres_next_upstream(ngx_http_request_t *r, ngx_int_t ft_type) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ft_type = %xi", ft_type);
    ngx_uint_t state = ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404 ? NGX_PEER_NEXT : NGX_PEER_FAILED;
    ngx_http_upstream_t *u = r->upstream;
    if (ft_type != NGX_HTTP_UPSTREAM_FT_NOLIVE) u->peer.free(&u->peer, u->peer.data, state);
    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT, "ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT");
    ngx_uint_t status;
    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) status = 0; else switch(ft_type) {
        case NGX_HTTP_UPSTREAM_FT_TIMEOUT: status = NGX_HTTP_GATEWAY_TIME_OUT; break;
        case NGX_HTTP_UPSTREAM_FT_HTTP_500: status = NGX_HTTP_INTERNAL_SERVER_ERROR; break;
        case NGX_HTTP_UPSTREAM_FT_HTTP_404: status = NGX_HTTP_NOT_FOUND; break;
        default: status = NGX_HTTP_BAD_GATEWAY; /* NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING never reach here */
    }
    if (r->connection->error) return ngx_http_upstream_finalize_request(r, u, NGX_HTTP_CLIENT_CLOSED_REQUEST);
    if (status) {
        u->state->status = status;
        if (!u->peer.tries || !(u->conf->next_upstream & ft_type)) return ngx_http_upstream_finalize_request(r, u, status);
    }
    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "fd = %i", u->peer.connection->fd);
        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
            u->peer.connection->pool = NULL;
        }
        ngx_close_connection(u->peer.connection);
    }
    if (!status) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!status"); status = NGX_HTTP_INTERNAL_SERVER_ERROR; /* TODO: ngx_http_upstream_connect(r, u); */ }
    return ngx_http_upstream_finalize_request(r, u, status);
}
