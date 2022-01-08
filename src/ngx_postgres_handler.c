#include "ngx_postgres_include.h"


static void ngx_postgres_data_read_or_write_handler(ngx_event_t *e) {
    ngx_connection_t *c = e->data;
    ngx_postgres_data_t *d = c->data;
    ngx_postgres_save_t *s = d->save;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_connection_t *co = r->connection;
    if (c->read->timedout) { c->read->timedout = 0; PQstatus(s->conn) == CONNECTION_OK ? ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT) : ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); goto run; }
    if (c->write->timedout) { c->write->timedout = 0; PQstatus(s->conn) == CONNECTION_OK ? ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT) : ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT); goto run; }
    if (ngx_http_upstream_test_connect(c) != NGX_OK) { ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); goto run; }
    if (!e->write && PQstatus(s->conn) == CONNECTION_OK && !PQconsumeInput(s->conn)) { ngx_postgres_log_error(NGX_LOG_ERR, e->log, 0, PQerrorMessageMy(s->conn), "!PQconsumeInput"); ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); goto run; }
    ngx_int_t rc = NGX_OK;
    if (!e->write && PQstatus(s->conn) == CONNECTION_OK && rc == NGX_OK) rc = ngx_postgres_notify(s);
    while (PQstatus(s->conn) == CONNECTION_OK && (s->res = PQgetResult(s->conn))) {
        if (e->write) {
            if (rc == NGX_OK && s->write_handler) rc = s->write_handler(s);
        } else {
            if (rc == NGX_OK && s->read_handler) rc = s->read_handler(s);
        }
        PQclear(s->res);
    }
    s->res = NULL;
    if (e->write) {
        if (rc == NGX_OK && s->write_handler) rc = s->write_handler(s);
    } else {
        if (rc == NGX_OK && s->read_handler) rc = s->read_handler(s);
    }
    switch (rc) {
        case NGX_ERROR: ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR); break;
        case NGX_AGAIN: break;
        default: ngx_http_upstream_finalize_request(r, u, rc == NGX_OK && u->out_bufs ? NGX_HTTP_OK : rc);
    }
run:
    ngx_http_run_posted_requests(co);
}


void ngx_postgres_data_read_handler(ngx_event_t *e) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->log, 0, "%s", __func__);
    ngx_postgres_data_read_or_write_handler(e);
}


void ngx_postgres_data_write_handler(ngx_event_t *e) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->log, 0, "%s", __func__);
    ngx_postgres_data_read_or_write_handler(e);
}


static ngx_int_t ngx_postgres_create_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (plc->complex.value.data) { // use complex value
        ngx_str_t host;
        if (ngx_http_complex_value(r, &plc->complex, &host) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
        if (!host.len) {
            ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "empty \"postgres_pass\" (was: \"%V\") in location \"%V\"", &plc->complex.value, &core->name);
            return NGX_ERROR;
        }
        if (!(u->resolved = ngx_pcalloc(r->pool, sizeof(*u->resolved)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        u->resolved->host = host;
        u->resolved->no_port = 1;
    }
    u->request_sent = 1; // force to reinit_request
    return NGX_OK;
}


static ngx_int_t ngx_postgres_reinit_request(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return NGX_ERROR; }
    ngx_postgres_data_t *d = u->peer.data;
    ngx_postgres_save_t *s = d->save;
    ngx_connection_t *c = s->connection;
    c->data = d;
    c->read->handler = ngx_postgres_data_read_handler;
    c->write->handler = ngx_postgres_data_write_handler;
    r->state = 0;
    return NGX_OK;
}


static void ngx_postgres_output(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->headers_out.status) r->headers_out.status = NGX_HTTP_OK;
    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return;
    ngx_http_upstream_t *u = r->upstream;
    u->header_sent = 1;
    if (!u->out_bufs) return;
    u->out_bufs->next = NULL;
    ngx_buf_t *b = u->out_bufs->buf;
    if (r == r->main && !r->post_action) b->last_buf = 1; else {
        b->sync = 1;
        b->last_in_chain = 1;
    }
    if (ngx_http_output_filter(r, u->out_bufs) != NGX_OK) return;
    ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs, &u->out_bufs, u->output.tag);
}


static void ngx_postgres_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    ngx_http_upstream_t *u = r->upstream;
    if (u->peer.get != ngx_postgres_peer_get) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer is not postgres"); return; }
    if (rc == NGX_OK || rc == NGX_HTTP_OK) ngx_postgres_output(r);
    ngx_postgres_data_t *d = u->peer.data;
    ngx_postgres_save_t *s = d->save;
    if (!s) return;
    ngx_connection_t *c = s->connection;
    if (!c) return;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
}


ngx_int_t ngx_postgres_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
//    if (r->subrequest_in_memory) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "subrequest_in_memory"); return NGX_HTTP_INTERNAL_SERVER_ERROR; } // TODO: add support for subrequest in memory by emitting output into u->buffer instead
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (!plc->query.nelts) {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "missing \"postgres_query\" in location \"%V\"", &core->name);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_postgres_query_t *queryelts = plc->query.elts;
    ngx_uint_t i;
    for (i = 0; i < plc->query.nelts; i++) if (!queryelts[i].method || queryelts[i].method & r->method) break;
    if (i == plc->query.nelts) return NGX_HTTP_NOT_ALLOWED;
    ngx_int_t rc;
    if (!plc->read_request_body && (rc = ngx_http_discard_request_body(r)) != NGX_OK) return rc;
    if (ngx_http_upstream_create(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    ngx_str_set(&u->schema, "postgres://");
    u->output.tag = (ngx_buf_tag_t)&ngx_postgres_module;
    u->conf = &plc->upstream;
    u->create_request = ngx_postgres_create_request;
    u->finalize_request = ngx_postgres_finalize_request;
    u->reinit_request = ngx_postgres_reinit_request;
    r->state = 0;
    u->buffering = plc->upstream.buffering;
    if (!plc->upstream.request_buffering && plc->upstream.pass_request_body && !r->headers_in.chunked) r->request_body_no_buffering = 1;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
#else
    if ((rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init_my)) >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
#endif
    return NGX_DONE;
}


u_char *ngx_postgres_log_error_handler(ngx_log_t *log, u_char *buf, size_t len) {
    u_char *p = buf;
    ngx_postgres_log_t *ngx_log_original = log->data;
    log->data = ngx_log_original->data;
    log->handler = ngx_log_original->handler;
    if (log->handler) p = log->handler(log, buf, len);
    len -= p - buf;
    buf = p;
    p = ngx_snprintf(buf, len, "\n%s", ngx_log_original->message);
    len -= p - buf;
    buf = p;
    return buf;
}
