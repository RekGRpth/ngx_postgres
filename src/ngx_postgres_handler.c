/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


ngx_int_t ngx_postgres_test_connect(ngx_connection_t *c) {
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
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: %s", __func__);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    if (u->peer.connection->write->timedout) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); return; }
    if (ngx_postgres_test_connect(u->peer.connection) != NGX_OK) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); return; }
    ngx_postgres_process_events(r);
}


static void ngx_postgres_read_event_handler(ngx_http_request_t *r, ngx_http_upstream_t *u) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: %s", __func__);
    u->request_sent = 1; /* just to ensure u->reinit_request always gets called for upstream_next */
    if (u->peer.connection->read->timedout) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); return; }
    if (ngx_postgres_test_connect(u->peer.connection) != NGX_OK) { ngx_postgres_next_upstream(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); return; }
    ngx_postgres_process_events(r);
}


static ngx_int_t ngx_postgres_create_request(ngx_http_request_t *r) {
    r->upstream->request_bufs = NULL;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_reinit_request(ngx_http_request_t *r) {
    /* override the read/write event handler to our own */
    r->upstream->write_event_handler = ngx_postgres_write_event_handler;
    r->upstream->read_event_handler = ngx_postgres_read_event_handler;
    return NGX_OK;
}


static void ngx_postgres_abort_request(ngx_http_request_t *r) { }


static void ngx_postgres_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    if (rc == NGX_OK) ngx_postgres_output_chain(r);
}


static ngx_int_t ngx_postgres_process_header(ngx_http_request_t *r) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: ngx_postgres_process_header should not be called by the upstream");
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_input_filter_init(void *data) {
    ngx_http_request_t *r = data;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: ngx_postgres_input_filter_init should not be called by the upstream");
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_input_filter(void *data, ssize_t bytes) {
    ngx_http_request_t *r = data;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: ngx_postgres_input_filter should not be called by the upstream");
    return NGX_ERROR;
}


ngx_http_upstream_srv_conf_t *ngx_postgres_find_upstream(ngx_http_request_t *r, ngx_url_t *url) {
    ngx_http_upstream_main_conf_t *m = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    ngx_http_upstream_srv_conf_t **s = m->upstreams.elts;
    for (ngx_uint_t i = 0; i < m->upstreams.nelts; i++) if (s[i]->host.len == url->host.len && !ngx_strncasecmp(s[i]->host.data, url->host.data, url->host.len)) return s[i];
    return NULL;
}


ngx_int_t ngx_postgres_handler(ngx_http_request_t *r) {
    /* TODO: add support for subrequest in memory by emitting output into u->buffer instead */
    if (r->subrequest_in_memory) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: ngx_postgres module does not support subrequests in memory"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (!location_conf->query && !(location_conf->methods_set & r->method)) {
        if (location_conf->methods_set) return NGX_HTTP_NOT_ALLOWED;
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: missing \"postgres_query\" in location \"%V\"", &core_loc_conf->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (location_conf->upstream_cv) { /* use complex value */
        ngx_str_t host;
        if (ngx_http_complex_value(r, location_conf->upstream_cv, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        if (!host.len) {
            ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: empty \"postgres_pass\" (was: \"%V\") in location \"%V\"", &location_conf->upstream_cv->value, &core_loc_conf->name);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.host = host;
        url.no_resolve = 1;
        if (!(location_conf->upstream.upstream = ngx_postgres_find_upstream(r, &url))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: upstream name \"%V\" not found", &host); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    }
    ngx_postgres_context_t *context = ngx_pcalloc(r->pool, sizeof(ngx_postgres_context_t));
    if (!context) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    context->nfields = NGX_ERROR;
    context->ntuples = NGX_ERROR;
    context->cmdTuples = NGX_ERROR;
    if (location_conf->variables) {
        if (!(context->variables = ngx_array_create(r->pool, location_conf->variables->nelts, sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        /* fake ngx_array_push'ing */
        context->variables->nelts = location_conf->variables->nelts;
        ngx_memzero(context->variables->elts, context->variables->nelts * context->variables->size);
    }
    ngx_http_set_ctx(r, context, ngx_postgres_module);
    r->upstream->schema.len = sizeof("postgres://") - 1;
    r->upstream->schema.data = (u_char *) "postgres://";
    r->upstream->output.tag = (ngx_buf_tag_t) &ngx_postgres_module;
    r->upstream->conf = &location_conf->upstream;
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
        if (r->upstream->peer.connection->pool) ngx_destroy_pool(r->upstream->peer.connection->pool);
        ngx_free_connection(r->upstream->peer.connection);
        r->upstream->peer.connection = NULL;
        ngx_postgres_finalize_upstream(r, r->upstream, NGX_HTTP_SERVICE_UNAVAILABLE);
    }
    return NGX_DONE;
}


void ngx_postgres_finalize_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: finalize http upstream request: %i (%p ~ %p)", rc, r->upstream, u);
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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: close http upstream connection: %d", u->peer.connection->fd);
        if (u->peer.connection->pool) ngx_destroy_pool(u->peer.connection->pool);
        ngx_close_connection(u->peer.connection);
    }
    u->peer.connection = NULL;
    if (u->pipe && u->pipe->temp_file) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: http upstream temp fd: %d", u->pipe->temp_file->file.fd);
    if (u->header_sent && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)) rc = 0;
    if (rc == NGX_DECLINED) return;
    if (!rc) rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, rc);
}


void ngx_postgres_next_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t ft_type) {
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: http next upstream, %xi (%p ~ %p)", ft_type, r->upstream, u);
    ngx_uint_t state = ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404 ? NGX_PEER_NEXT : NGX_PEER_FAILED;
    if (ft_type != NGX_HTTP_UPSTREAM_FT_NOLIVE) u->peer.free(&u->peer, u->peer.data, state);
    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT, "postgres: upstream timed out");
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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: close http upstream connection: %d", u->peer.connection->fd);
        if (u->peer.connection->pool) ngx_destroy_pool(u->peer.connection->pool);
        ngx_close_connection(u->peer.connection);
    }
    if (!status) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: %s:%d", __FILE__, __LINE__); status = NGX_HTTP_INTERNAL_SERVER_ERROR; /* TODO: ngx_http_upstream_connect(r, u); */ }
    return ngx_postgres_finalize_upstream(r, u, status);
}
