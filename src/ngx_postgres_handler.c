#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"


ngx_int_t ngx_postgres_test_connect(ngx_connection_t *c) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (c->write->pending_eof) { (void) ngx_connection_error(c, c->write->kq_errno, "kevent() reported that connect() failed"); return NGX_ERROR; }
    } else
#endif
    {
        int err = 0;
        socklen_t len = sizeof(int);
        /* BSDs and Linux return 0 and set a pending error in err, Solaris returns -1 and sets errno */
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) err = ngx_errno;
        if (err) { (void) ngx_connection_error(c, err, "connect() failed"); return NGX_ERROR; }
    }
    return NGX_OK;
}


static void ngx_postgres_write_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s (%p ~ %p)", __func__, r->upstream, u);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    if (u->peer.connection->write->timedout) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); return; }
    if (ngx_postgres_test_connect(u->peer.connection) != NGX_OK) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); return; }
    ngx_postgres_process_events(r);
}


static void ngx_postgres_read_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s (%p ~ %p)", __func__, r->upstream, u);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    if (u->peer.connection->read->timedout) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); return; }
    if (ngx_postgres_test_connect(u->peer.connection) != NGX_OK) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); return; }
    ngx_postgres_process_events(r);
}


static ngx_int_t ngx_postgres_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    r->upstream->request_bufs = NULL;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    /* override the read/write event handler to our own */
    r->upstream->write_event_handler = ngx_postgres_write_event_handler;
    r->upstream->read_event_handler = ngx_postgres_read_event_handler;
    return NGX_OK;
}


static void ngx_postgres_abort_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}


static void ngx_postgres_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s %i", __func__, rc);
    if (rc == NGX_OK) ngx_postgres_output_chain(r);
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
    ngx_http_upstream_main_conf_t *m = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    ngx_http_upstream_srv_conf_t **s = m->upstreams.elts;
    for (ngx_uint_t i = 0; i < m->upstreams.nelts; i++) if (s[i]->host.len == url->host.len && !ngx_strncasecmp(s[i]->host.data, url->host.data, url->host.len)) return s[i];
    return NULL;
}


ngx_int_t ngx_postgres_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (r->subrequest_in_memory) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "r->subrequest_in_memory"); return NGX_HTTP_INTERNAL_SERVER_ERROR; } /* TODO: add support for subrequest in memory by emitting output into u->buffer instead */
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (!location->query.sql.data) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "missing \"postgres_query\" in location \"%V\"", &core_loc_conf->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (location->complex) { /* use complex value */
        ngx_str_t host;
        if (ngx_http_complex_value(r, location->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        if (!host.len) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"postgres_pass\" (was: \"%V\") in location \"%V\"", &location->complex->value, &core_loc_conf->name);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.host = host;
        url.no_resolve = 1;
        if (!(location->upstream.upstream = ngx_postgres_find_upstream(r, &url))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream name \"%V\" not found", &host); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    }
    r->upstream->schema.len = sizeof("postgres://") - 1;
    r->upstream->schema.data = (u_char *) "postgres://";
    r->upstream->output.tag = (ngx_buf_tag_t) &ngx_postgres_module;
    r->upstream->conf = &location->upstream;
    r->upstream->create_request = ngx_postgres_create_request;
    r->upstream->reinit_request = ngx_postgres_reinit_request;
    r->upstream->process_header = ngx_postgres_process_header;
    r->upstream->abort_request = ngx_postgres_abort_request;
    r->upstream->finalize_request = ngx_postgres_finalize_request;
    /* we bypass the upstream input filter mechanism in ngx_http_upstream_process_headers */
    r->upstream->input_filter_init = ngx_postgres_input_filter_init;
    r->upstream->input_filter = ngx_postgres_input_filter;
    r->upstream->input_filter_ctx = NULL;
    r->main->count++;
    ngx_http_upstream_init(r);
    /* override the read/write event handler to our own */
    r->upstream->write_event_handler = ngx_postgres_write_event_handler;
    r->upstream->read_event_handler = ngx_postgres_read_event_handler;
    /* a bit hack-ish way to return error response (clean-up part) */
    if (r->upstream->peer.connection && !r->upstream->peer.connection->fd) {
        if (r->upstream->peer.connection->write->timer_set) ngx_del_timer(r->upstream->peer.connection->write);
        if (r->upstream->peer.connection->pool) {
            ngx_destroy_pool(r->upstream->peer.connection->pool);
            r->upstream->peer.connection->pool = NULL;
        }
        ngx_free_connection(r->upstream->peer.connection);
        r->upstream->peer.connection = NULL;
        ngx_postgres_finalize_upstream(r, r->upstream, NGX_HTTP_SERVICE_UNAVAILABLE);
    }
    return NGX_DONE;
}


void ngx_postgres_finalize_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "finalize http upstream request: %i (%p ~ %p)", rc, r->upstream, u);
    if (u->cleanup) *u->cleanup = NULL;
    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }
    if (u->state && u->state->response_time) {
        u->state->response_time = ngx_current_msec - u->state->response_time;
        if (u->pipe) u->state->response_length = u->pipe->read_length;
    }
    if (u->finalize_request) u->finalize_request(r, rc);
    if (u->peer.free) u->peer.free(&u->peer, u->peer.data, 0);
    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "close http upstream connection: %i", u->peer.connection->fd);
        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
            u->peer.connection->pool = NULL;
        }
        ngx_close_connection(u->peer.connection);
    }
    u->peer.connection = NULL;
    if (u->pipe && u->pipe->temp_file) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http upstream temp fd: %i", u->pipe->temp_file->file.fd); }
    if (u->header_sent && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)) rc = 0;
    if (rc == NGX_DECLINED) return;
    if (!rc) rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, rc);
}


void ngx_postgres_next_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t ft_type) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http next upstream, %xi (%p ~ %p)", ft_type, r->upstream, u);
    ngx_uint_t state = ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404 ? NGX_PEER_NEXT : NGX_PEER_FAILED;
    if (ft_type != NGX_HTTP_UPSTREAM_FT_NOLIVE) u->peer.free(&u->peer, u->peer.data, state);
    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT, "ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT");
    ngx_uint_t status;
    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) status = 0; else switch(ft_type) {
        case NGX_HTTP_UPSTREAM_FT_TIMEOUT: status = NGX_HTTP_GATEWAY_TIME_OUT; break;
        case NGX_HTTP_UPSTREAM_FT_HTTP_500: status = NGX_HTTP_INTERNAL_SERVER_ERROR; break;
        case NGX_HTTP_UPSTREAM_FT_HTTP_404: status = NGX_HTTP_NOT_FOUND; break;
        default: status = NGX_HTTP_BAD_GATEWAY; /* NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING never reach here */
    }
    if (r->connection->error) { ngx_postgres_finalize_upstream(r, u, NGX_HTTP_CLIENT_CLOSED_REQUEST); return; }
    if (status) {
        u->state->status = status;
        if (!u->peer.tries || !(u->conf->next_upstream & ft_type)) { ngx_postgres_finalize_upstream(r, u, status); return; }
    }
    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "close http upstream connection: %i", u->peer.connection->fd);
        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
            u->peer.connection->pool = NULL;
        }
        ngx_close_connection(u->peer.connection);
    }
    if (!status) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!status"); status = NGX_HTTP_INTERNAL_SERVER_ERROR; /* TODO: ngx_http_upstream_connect(r, u); */ }
    return ngx_postgres_finalize_upstream(r, u, status);
}
