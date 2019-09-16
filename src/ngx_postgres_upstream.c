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

#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf);
static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
static void ngx_postgres_write_handler(ngx_event_t *ev);
static void ngx_postgres_read_handler(ngx_event_t *ev);
static void ngx_postgres_process_notify(ngx_log_t *log, ngx_pool_t *pool, PGconn *conn);
static void ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *, ngx_postgres_peer_data_t *, ngx_uint_t);
static ngx_int_t ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *, ngx_postgres_peer_data_t *);
static ngx_int_t ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *, ngx_postgres_peer_data_t *);
static ngx_int_t ngx_postgres_keepalive_init(ngx_pool_t *, ngx_postgres_server_conf_t *);
static ngx_str_t PQescapeInternal(ngx_pool_t *pool, const u_char *str, size_t len, ngx_flag_t as_ident);


ngx_int_t ngx_postgres_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    upstream_srv_conf->peer.init = ngx_postgres_upstream_init_peer;
    ngx_postgres_server_conf_t *server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    if (!upstream_srv_conf->servers || !upstream_srv_conf->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &upstream_srv_conf->host, upstream_srv_conf->file_name, upstream_srv_conf->line); return NGX_ERROR; }
    ngx_postgres_server_t *server = upstream_srv_conf->servers->elts;
    ngx_uint_t n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) n += server[i].naddrs;
    ngx_postgres_peers_t *peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_peers_t) + sizeof(ngx_postgres_peer_t) * (n - 1));
    if (!peers) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    peers->single = (n == 1);
    peers->number = n;
    n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < server[i].naddrs; j++) {
            ngx_postgres_peer_t *peer = &peers->peer[n];
            peer->sockaddr = server[i].addrs[j].sockaddr;
            peer->socklen = server[i].addrs[j].socklen;
            peer->name = server[i].addrs[j].name;
            if (!(peer->host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (!(peer->host.len = ngx_sock_ntop(peer->sockaddr, peer->socklen, peer->host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            size_t len = server[i].family == AF_UNIX ? sizeof("host=%s") - 1 - 1 + peer->host.len - 5 : sizeof("hostaddr=%V") - 1 - 1 + peer->host.len;
            len += sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1;
            if (server[i].dbname.len) len += sizeof(" dbname=%V") - 1 - 1 + server[i].dbname.len;
            if (server[i].user.len) len += sizeof(" user=%V") - 1 - 1 + server[i].user.len;
            if (server[i].password.len) len += sizeof(" password=%V") - 1 - 1 + server[i].password.len;
            if (server[i].application_name.len) len += sizeof(" application_name=%V") - 1 - 1 + server[i].application_name.len;
            if (!(peer->connstring = ngx_pnalloc(cf->pool, len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            u_char *last = peer->connstring;
            last = server[i].family == AF_UNIX ? ngx_snprintf(last, sizeof("host=%s") - 1 - 1 + peer->host.len - 5, "host=%s", &peer->host.data[5]) : ngx_snprintf(last, sizeof("hostaddr=%V") - 1 - 1 + peer->host.len, "hostaddr=%V", &peer->host);
            last = ngx_snprintf(last, sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1, " port=%d", server[i].port);
            if (server[i].dbname.len) last = ngx_snprintf(last, sizeof(" dbname=%V") - 1 - 1 + server[i].dbname.len, " dbname=%V", &server[i].dbname);
            if (server[i].user.len) last = ngx_snprintf(last, sizeof(" user=%V") - 1 - 1 + server[i].user.len, " user=%V", &server[i].user);
            if (server[i].password.len) last = ngx_snprintf(last, sizeof(" password=%V") - 1 - 1 + server[i].password.len, " password=%V", &server[i].password);
            if (server[i].application_name.len) last = ngx_snprintf(last, sizeof(" application_name=%V") - 1 - 1 + server[i].application_name.len, " application_name=%V", &server[i].application_name);
            *last = '\0';
            n++;
        }
    }
    server_conf->peers = peers;
    server_conf->active_conns = 0;
    if (server_conf->max_cached) return ngx_postgres_keepalive_init(cf->pool, server_conf);
    return NGX_OK;
}


static ngx_str_t PQescapeInternal(ngx_pool_t *pool, const u_char *str, size_t len, ngx_flag_t as_ident) {
    ngx_str_t result = ngx_null_string;
    u_char quote_char = as_ident ? '"' : '\'';
    ngx_uint_t num_backslashes = 0;
    ngx_uint_t num_quotes = 0;
    const u_char *s;
    for (s = str; (size_t)(s - str) < len && *s != '\0'; ++s) if (*s == quote_char) ++num_quotes; else if (*s == '\\') ++num_backslashes;
    size_t input_len = s - str;
    size_t result_size = input_len + num_quotes + 3;
    if (!as_ident && num_backslashes > 0) result_size += num_backslashes + 2;
    u_char *rp = ngx_pnalloc(pool, result_size);
    if (!rp) return result;
    result.data = rp;
    if (!as_ident && num_backslashes > 0) { *rp++ = ' '; *rp++ = 'E'; }
    *rp++ = quote_char;
    if (!num_quotes && (!num_backslashes || as_ident)) rp = ngx_copy(rp, str, input_len);
    else for (s = str; (size_t)(s - str) < input_len; ++s) if (*s == quote_char || (!as_ident && *s == '\\')) { *rp++ = *s; *rp++ = *s; } else *rp++ = *s;
    *rp++ = quote_char;
    *rp = '\0';
    result.len = rp - result.data;
    return result;
}


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    ngx_postgres_peer_data_t *peer_data = ngx_pcalloc(r->pool, sizeof(ngx_postgres_peer_data_t));
    if (!peer_data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    peer_data->request = r;
    ngx_postgres_server_conf_t *server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    peer_data->server_conf = server_conf;
    if (!(peer_data->statements = ngx_pcalloc(r->pool, server_conf->max_statements * sizeof(ngx_postgres_statement_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    u->peer.data = peer_data;
    u->peer.get = ngx_postgres_upstream_get_peer;
    u->peer.free = ngx_postgres_upstream_free_peer;
    ngx_postgres_query_t *query;
    if (location_conf->methods_set & r->method) {
        query = location_conf->methods->elts;
        ngx_uint_t i;
        for (i = 0; i < location_conf->methods->nelts; i++) if (query[i].methods & r->method) { query = &query[i]; break; }
        if (i == location_conf->methods->nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    } else query = location_conf->query;
    if (query->params->nelts) {
        ngx_postgres_param_t *param = query->params->elts;
        peer_data->nParams = query->params->nelts;
        if (!(peer_data->paramTypes = ngx_pnalloc(r->pool, query->params->nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (!(peer_data->paramValues = ngx_pnalloc(r->pool, query->params->nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->params->nelts; i++) {
            peer_data->paramTypes[i] = param[i].oid;
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[i].index);
            if (!value || !value->data || !value->len) peer_data->paramValues[i] = NULL; else {
                if (!(peer_data->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                (void) ngx_cpystrn(peer_data->paramValues[i], value->data, value->len + 1);
            }
        }
    }
    ngx_str_t sql = query->sql;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: sql = `%V`", &sql);
    if (query->ids->nelts) {
        ngx_uint_t *id = query->ids->elts;
        ngx_str_t *ids = ngx_pnalloc(r->pool, query->ids->nelts * sizeof(ngx_str_t));
        if (!ids) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        sql.len = query->sql.len - 2 * query->ids->nelts;
        for (ngx_uint_t i = 0; i < query->ids->nelts; i++) {
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, id[i]);
            if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                ids[i] = PQescapeInternal(r->pool, value->data, value->len, 1);
                if (!ids[i].len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to escape %*.*s", value->len, value->len, value->data); return NGX_ERROR; }
                sql.len += ids[i].len;
            }
        }
        if (!(sql.data = ngx_pnalloc(r->pool, sql.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        switch (query->ids->nelts - 1) {
//            case 0: if ((len = ngx_snprintf(sql.data, sql.len, (const char *)query->sql.data, &ids[0]) - sql.data) != sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%ul!=%ul, %s:%d", len, sql.len, __FILE__, __LINE__); return NGX_ERROR; } break;
            case 0: if (ngx_snprintf(sql.data, sql.len, (const char *)query->sql.data, &ids[0]) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; } break;
            case 1: if (ngx_snprintf(sql.data, sql.len, (const char *)query->sql.data, &ids[0], &ids[1]) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; } break;
            case 2: if (ngx_snprintf(sql.data, sql.len, (const char *)query->sql.data, &ids[0], &ids[1], &ids[2]) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; } break;
        }
    }
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: sql = `%V`", &sql);
    peer_data->resultFormat = location_conf->binary;
    context->sql = sql; /* set $postgres_query */
    if (!(peer_data->command = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    (void) ngx_cpystrn(peer_data->command, sql.data, sql.len + 1);
    if (server_conf->max_statements && !query->listen) {
        peer_data->hash = ngx_hash_key(sql.data, sql.len);
        if (!(peer_data->stmtName = ngx_pnalloc(r->pool, 32))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        u_char *last = ngx_snprintf(peer_data->stmtName, 31, "ngx_%ul", (unsigned long)peer_data->hash);
        *last = '\0';
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_postgres_peer_data_t *peer_data = data;
    peer_data->failed = 0;
    if (peer_data->server_conf->max_cached && peer_data->server_conf->single && ngx_postgres_keepalive_get_peer_single(pc, peer_data) != NGX_DECLINED) { /* re-use keepalive peer */
        peer_data->state = peer_data->server_conf->max_statements ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(peer_data->request);
        return NGX_AGAIN;
    }
    if (peer_data->server_conf->current > peer_data->server_conf->peers->number - 1) peer_data->server_conf->current = 0;
    ngx_postgres_peer_t *peer = &peer_data->server_conf->peers->peer[peer_data->server_conf->current++];
    peer_data->name = peer->name;
    peer_data->sockaddr = *peer->sockaddr;
    pc->name = &peer_data->name;
    pc->sockaddr = &peer_data->sockaddr;
    pc->socklen = peer->socklen;
    pc->cached = 0;
    if (peer_data->server_conf->max_cached && !peer_data->server_conf->single && ngx_postgres_keepalive_get_peer_multi(pc, peer_data) != NGX_DECLINED) { /* re-use keepalive peer */
        peer_data->state = peer_data->server_conf->max_statements ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(peer_data->request);
        return NGX_AGAIN;
    }
    if (peer_data->server_conf->reject && peer_data->server_conf->active_conns >= peer_data->server_conf->max_cached) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0, "postgres: keepalive connection pool is full, rejecting request to upstream \"%V\"", &peer->name);
        pc->connection = ngx_get_connection(0, pc->log); /* a bit hack-ish way to return error response (setup part) */
        return NGX_AGAIN;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PostgreSQL connstring: %s", peer->connstring);
    /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    peer_data->conn = PQconnectStart((const char *)peer->connstring);
    if (PQstatus(peer_data->conn) == CONNECTION_BAD || PQsetnonblocking(peer_data->conn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: connection failed: %s in upstream \"%V\"", PQerrorMessage(peer_data->conn), &peer->name);
        PQfinish(peer_data->conn);
        peer_data->conn = NULL;
        return NGX_DECLINED;
    }
    peer_data->server_conf->active_conns++; /* take spot in keepalive connection pool */
    int fd = PQsocket(peer_data->conn); /* add the file descriptor (fd) into an nginx connection structure */
    if (fd == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to get connection fd"); goto invalid; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: connection fd:%d", fd);
    if (!(pc->connection = ngx_get_connection(fd, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to get a free nginx connection"); goto invalid; }
    pc->connection->log = pc->log;
    pc->connection->log_error = pc->log_error;
    pc->connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    ngx_event_t *rev = pc->connection->read;
    ngx_event_t *wev = pc->connection->write;
    rev->log = pc->log;
    wev->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(pc->connection) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
    } else {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
    }
    peer_data->state = state_db_connect;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to add nginx connection");
invalid:
    ngx_postgres_free_connection(pc->connection, peer_data->conn, peer_data->server_conf);
    return NGX_ERROR;
}


static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_postgres_peer_data_t *peer_data = data;
    if (peer_data->server_conf->max_cached) ngx_postgres_keepalive_free_peer(pc, peer_data, state);
    if (pc->connection) {
        ngx_postgres_free_connection(pc->connection, peer_data->conn, peer_data->server_conf);
        peer_data->conn = NULL;
        pc->connection = NULL;
    }
}


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *peer) {
    return (peer->get == ngx_postgres_upstream_get_peer);
}


void ngx_postgres_free_connection(ngx_connection_t *c, PGconn *conn, ngx_postgres_server_conf_t *server_conf) {
    PQfinish(conn);
    if (c) {
        ngx_event_t *rev = c->read;
        ngx_event_t *wev = c->write;
        if (rev->timer_set) ngx_del_timer(rev);
        if (wev->timer_set) ngx_del_timer(wev);
        if (ngx_del_conn) ngx_del_conn(c, NGX_CLOSE_EVENT); else {
            if (rev->active || rev->disabled) ngx_del_event(rev, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            if (wev->active || wev->disabled) ngx_del_event(wev, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
        if (rev->posted) { ngx_delete_posted_event(rev); }
        if (wev->posted) { ngx_delete_posted_event(wev); }
        rev->closed = 1;
        wev->closed = 1;
        if (c->pool) ngx_destroy_pool(c->pool);
        ngx_free_connection(c);
        c->fd = (ngx_socket_t) -1;
    }
    /* free spot in keepalive connection pool */
    server_conf->active_conns--;
}


static ngx_int_t ngx_postgres_keepalive_init(ngx_pool_t *pool, ngx_postgres_server_conf_t *server_conf) {
    ngx_postgres_cached_t *cached = ngx_pcalloc(pool, sizeof(ngx_postgres_cached_t) * server_conf->max_cached);
    if (!cached) { ngx_log_error(NGX_LOG_ERR, pool->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_queue_init(&server_conf->cache);
    ngx_queue_init(&server_conf->free);
    for (ngx_uint_t i = 0; i < server_conf->max_cached; i++) {
        ngx_queue_insert_head(&server_conf->free, &cached[i].queue);
        cached[i].server_conf = server_conf;
        if (server_conf->max_statements && !(cached[i].statements = ngx_pcalloc(pool, server_conf->max_statements * sizeof(ngx_postgres_statement_t)))) { ngx_log_error(NGX_LOG_ERR, pool->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data) {
    if (ngx_queue_empty(&peer_data->server_conf->cache)) return NGX_DECLINED;
    ngx_queue_t *q = ngx_queue_head(&peer_data->server_conf->cache);
    ngx_queue_remove(q);
    ngx_postgres_cached_t *cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
    ngx_queue_insert_head(&peer_data->server_conf->free, q);
    cached->connection->idle = 0;
    cached->connection->log = pc->log;
    cached->connection->pool->log = pc->log;
    cached->connection->read->log = pc->log;
    cached->connection->write->log = pc->log;
    peer_data->name = cached->name;
    peer_data->sockaddr = cached->sockaddr;
    peer_data->conn = cached->conn;
    pc->connection = cached->connection;
    pc->cached = 1;
    pc->name = &peer_data->name;
    pc->sockaddr = &peer_data->sockaddr;
    pc->socklen = cached->socklen;
    for (ngx_uint_t j = 0; j < peer_data->server_conf->max_statements; j++) peer_data->statements[j] = cached->statements[j]; /* Inherit list of prepared statements */
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data) {
    ngx_queue_t *cache = &peer_data->server_conf->cache;
    for (ngx_queue_t *q = ngx_queue_head(cache); q != ngx_queue_sentinel(cache); q = ngx_queue_next(q)) {
        ngx_postgres_cached_t *cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
        if (ngx_memn2cmp((u_char *) &cached->sockaddr, (u_char *) pc->sockaddr, cached->socklen, pc->socklen)) continue;
        ngx_queue_remove(q);
        ngx_queue_insert_head(&peer_data->server_conf->free, q);
        cached->connection->idle = 0;
        cached->connection->log = pc->log;
        cached->connection->pool->log = pc->log;
        cached->connection->read->log = pc->log;
        cached->connection->write->log = pc->log;
        pc->connection = cached->connection;
        pc->cached = 1;
        /* we do not need to resume the peer name, because we already take the right value outside */
        peer_data->conn = cached->conn;
        for (ngx_uint_t j = 0; j < peer_data->server_conf->max_statements; j++) peer_data->statements[j] = cached->statements[j]; /* Inherit list of prepared statements */
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


static void ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data, ngx_uint_t state) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: free keepalive peer");
    if (state & NGX_PEER_FAILED) peer_data->failed = 1;
    if (!peer_data->failed && pc->connection && peer_data->request->upstream->headers_in.status_n == NGX_HTTP_OK) {
        ngx_connection_t *c = pc->connection;
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
        if (c->write->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT) && ngx_del_event(c->write, NGX_WRITE_EVENT, 0) != NGX_OK) return;
        pc->connection = NULL;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: free keepalive peer: saving connection %p", c);
        ngx_queue_t *q;
        ngx_postgres_cached_t *cached;
        if (ngx_queue_empty(&peer_data->server_conf->free)) { /* connection pool is already full */
            q = ngx_queue_last(&peer_data->server_conf->cache);
            ngx_queue_remove(q);
            cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
            ngx_postgres_free_connection(cached->connection, cached->conn, peer_data->server_conf);
        } else {
            q = ngx_queue_head(&peer_data->server_conf->free);
            ngx_queue_remove(q);
            cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
        }
        for (ngx_uint_t j = 0; j < peer_data->server_conf->max_statements; j++) cached->statements[j] = peer_data->statements[j];
        cached->connection = c;
        ngx_queue_insert_head(&peer_data->server_conf->cache, q);
        c->write->handler = ngx_postgres_write_handler;
        c->read->handler = ngx_postgres_read_handler;
        c->data = cached;
        c->idle = 1;
        c->log = ngx_cycle->log;
        c->pool->log = ngx_cycle->log;
        c->read->log = ngx_cycle->log;
        c->write->log = ngx_cycle->log;
        cached->socklen = pc->socklen;
        ngx_memcpy(&cached->sockaddr, pc->sockaddr, pc->socklen);
        cached->conn = peer_data->conn;
        cached->name = peer_data->name;
    }
}


static void ngx_postgres_write_handler(ngx_event_t *ev) { }


static void ngx_postgres_read_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_postgres_cached_t *cached = c->data;
    if (c->close) goto close;
    if (!PQconsumeInput(cached->conn)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(cached->conn)); goto close; }
    if (PQisBusy(cached->conn)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "postgres: busy while keepalive"); goto close; }
    for (PGresult *res; (res = PQgetResult(cached->conn)); PQclear(res)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "postgres: received result on idle keepalive connection: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res)); }
    ngx_postgres_process_notify(c->log, c->pool, cached->conn);
    return;
close:
    ngx_postgres_free_connection(c, cached->conn, cached->server_conf);
    ngx_queue_remove(&cached->queue);
    ngx_queue_insert_head(&cached->server_conf->free, &cached->queue);
}


void ngx_postgres_process_notify(ngx_log_t *log, ngx_pool_t *pool, PGconn *conn) {
    for (PGnotify *notify; (notify = PQnotifies(conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, "postgres notify: relname=\"%s\", extra=\"%s\", be_pid=%d.", notify->relname, notify->extra, notify->be_pid);
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        switch (ngx_http_push_stream_add_msg_to_channel_my(log, &id, &text, NULL, NULL, 0, pool)) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, log, 0, "postgres notify error"); return;
            case NGX_DECLINED: {
                ngx_log_error(NGX_LOG_ERR, log, 0, "postgres notify declined");
                ngx_str_t channel = PQescapeInternal(pool, id.data, id.len, 1);
                if (!channel.len) { ngx_log_error(NGX_LOG_ERR, log, 0, "postgres: failed to escape %V", id); return; }
                u_char *command = ngx_pnalloc(pool, sizeof("UNLISTEN ") - 1 + channel.len + 1);
                if (!command) { ngx_log_error(NGX_LOG_ERR, log, 0, "%s:%d", __FILE__, __LINE__); return; }
                u_char *last = ngx_snprintf(command, sizeof("UNLISTEN ") - 1 + channel.len, "UNLISTEN %V", &channel);
                if (last != command + sizeof("UNLISTEN ") - 1 + channel.len) { ngx_log_error(NGX_LOG_ERR, log, 0, "%s:%d", __FILE__, __LINE__); return; }
                *last = '\0';
                if (!PQsendQuery(conn, (const char *)command)) { ngx_log_error(NGX_LOG_ERR, log, 0, "postgres: failed to send unlisten: %s", PQerrorMessage(conn)); return; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "postgres: unlisten %s sent successfully", command);
            } return;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "postgres notify ok"); return;
            default: ngx_log_error(NGX_LOG_ERR, log, 0, "postgres notify unknown"); return;
        }
    }
}
