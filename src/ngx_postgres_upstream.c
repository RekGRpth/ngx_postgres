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
#include "ngx_postgres_keepalive.h"
#include "ngx_postgres_processor.h"


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);


ngx_int_t ngx_postgres_upstream_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    uscf->peer.init = ngx_postgres_upstream_init_peer;
    ngx_postgres_upstream_srv_conf_t *pgscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_postgres_module);
    if (!uscf->servers || !uscf->servers->nelts) { ngx_log_error(NGX_LOG_ERR, cf->log, 0, "postgres: no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &uscf->host, uscf->file_name, uscf->line); return NGX_ERROR; }
    ngx_postgres_upstream_server_t *server = uscf->servers->elts;
    ngx_uint_t n = 0;
    for (ngx_uint_t i = 0; i < uscf->servers->nelts; i++) n += server[i].naddrs;
    ngx_postgres_upstream_peers_t *peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_upstream_peers_t) + sizeof(ngx_postgres_upstream_peer_t) * (n - 1));
    if (!peers) { ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    peers->single = (n == 1);
    peers->number = n;
    n = 0;
    for (ngx_uint_t i = 0; i < uscf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < server[i].naddrs; j++) {
            peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
            peers->peer[n].socklen = server[i].addrs[j].socklen;
            peers->peer[n].name = server[i].addrs[j].name;
            peers->peer[n].port = server[i].port;
            peers->peer[n].family = server[i].family;
            peers->peer[n].dbname = server[i].dbname;
            peers->peer[n].user = server[i].user;
            peers->peer[n].password = server[i].password;
            peers->peer[n].application_name = server[i].application_name;
            if (!(peers->peer[n].host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (!(peers->peer[n].host.len = ngx_sock_ntop(peers->peer[n].sockaddr, peers->peer[n].socklen, peers->peer[n].host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_log_error(NGX_LOG_ERR, cf->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            n++;
        }
    }
    pgscf->peers = peers;
    pgscf->active_conns = 0;
    if (pgscf->max_cached) return ngx_postgres_keepalive_init(cf->pool, pgscf);
    return NGX_OK;
}


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_postgres_upstream_peer_data_t *pgdt = ngx_pcalloc(r->pool, sizeof(ngx_postgres_upstream_peer_data_t));
    if (!pgdt) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    pgdt->upstream = u;
    pgdt->request = r;
    ngx_postgres_upstream_srv_conf_t *pgscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_postgres_module);
    ngx_postgres_loc_conf_t *pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    pgdt->srv_conf = pgscf;
    pgdt->loc_conf = pglcf;
    if (!(pgdt->statements = ngx_pcalloc(r->pool, pgscf->max_statements * sizeof(ngx_uint_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    u->peer.data = pgdt;
    u->peer.get = ngx_postgres_upstream_get_peer;
    u->peer.free = ngx_postgres_upstream_free_peer;
    ngx_postgres_query_t *query;
    if (pglcf->query.methods_set & r->method) {
        query = pglcf->query.methods.elts;
        ngx_uint_t i;
        for (i = 0; i < pglcf->query.methods.nelts; i++) if (query[i].methods & r->method) { query = &query[i]; break; }
        if (i == pglcf->query.methods.nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    } else query = pglcf->query.def;
    ngx_str_t sql;
    if (ngx_http_complex_value(r, &query->sql, &sql) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    if (!(pgdt->command = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    (void) ngx_cpystrn(pgdt->command, sql.data, sql.len + 1);
    pgdt->command_len = sql.len;
    if (query->args.nelts) {
        ngx_postgres_arg_t *arg = query->args.elts;
        pgdt->nParams = query->args.nelts;
        if (!(pgdt->paramTypes = ngx_pnalloc(r->pool, query->args.nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (!(pgdt->paramValues = ngx_pnalloc(r->pool, query->args.nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->args.nelts; i++) {
            pgdt->paramTypes[i] = arg[i].oid;
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, arg[i].index);
            if (!value || !value->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (!(pgdt->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            (void) ngx_cpystrn(pgdt->paramValues[i], value->data, value->len + 1);
        }
    }
    /* set $postgres_query */
    pgctx->var_query = sql;
    return NGX_OK;
}


static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_postgres_upstream_peer_data_t *pgdt = data;
    pgdt->failed = 0;
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->srv_conf;
    if (pgscf->max_cached && pgscf->single && ngx_postgres_keepalive_get_peer_single(pc, pgdt) != NGX_DECLINED) { /* re-use keepalive peer */
        pgdt->state = state_db_send_query;
        ngx_postgres_process_events(pgdt->request);
        return NGX_AGAIN;
    }
    ngx_postgres_upstream_peers_t *peers = pgscf->peers;
    if (pgscf->current > peers->number - 1) pgscf->current = 0;
    ngx_postgres_upstream_peer_t *peer = &peers->peer[pgscf->current++];
    pgdt->name.len = peer->name.len;
    pgdt->name.data = peer->name.data;
    pgdt->sockaddr = *peer->sockaddr;
    pc->name = &pgdt->name;
    pc->sockaddr = &pgdt->sockaddr;
    pc->socklen = peer->socklen;
    pc->cached = 0;
    if (pgscf->max_cached && !pgscf->single && ngx_postgres_keepalive_get_peer_multi(pc, pgdt) != NGX_DECLINED) { /* re-use keepalive peer */
        pgdt->state = state_db_send_query;
        ngx_postgres_process_events(pgdt->request);
        return NGX_AGAIN;
    }
    if (pgscf->reject && pgscf->active_conns >= pgscf->max_cached) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0, "postgres: keepalive connection pool is full, rejecting request to upstream \"%V\"", &peer->name);
        /* a bit hack-ish way to return error response (setup part) */
        pc->connection = ngx_get_connection(0, pc->log);
        return NGX_AGAIN;
    }
    /* sizeof("...") - 1 + 1 (for spaces and '\0' omitted */
    /* we hope that unix sockets connection string will be always shorter than tcp/ip one (because 'host' is shorter than 'hostaddr') */
    size_t len = peer->family == AF_UNIX ? sizeof("host=%s") - 1 - 1 + peer->host.len - 5 : sizeof("hostaddr=%V") - 1 - 1 + peer->host.len;
    len += sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1;
    if (peer->dbname.len) len += sizeof(" dbname=%V") - 1 - 1 + peer->dbname.len;
    if (peer->user.len) len += sizeof(" user=%V") - 1 - 1 + peer->user.len;
    if (peer->password.len) len += sizeof(" password=%V") - 1 - 1 + peer->password.len;
    if (peer->application_name.len) len += sizeof(" application_name=%V") - 1 - 1 + peer->application_name.len;
    u_char *connstring = ngx_pnalloc(pgdt->request->pool, len);
    if (!connstring) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    u_char *last = peer->family == AF_UNIX
        ? ngx_snprintf(connstring, sizeof("host=%s") - 1 - 1 + peer->host.len - 5, "host=%s", &peer->host.data[5])
        : ngx_snprintf(connstring, sizeof("hostaddr=%V") - 1 - 1 + peer->host.len, "hostaddr=%V", &peer->host);
    last = ngx_snprintf(last, sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1, " port=%d", peer->port);
    if (peer->dbname.len) last = ngx_snprintf(last, sizeof(" dbname=%V") - 1 - 1 + peer->dbname.len, " dbname=%V", &peer->dbname);
    if (peer->user.len) last = ngx_snprintf(last, sizeof(" user=%V") - 1 - 1 + peer->user.len, " user=%V", &peer->user);
    if (peer->password.len) last = ngx_snprintf(last, sizeof(" password=%V") - 1 - 1 + peer->password.len, " password=%V", &peer->password);
    if (peer->application_name.len) last = ngx_snprintf(last, sizeof(" application_name=%V") - 1 - 1 + peer->application_name.len, " application_name=%V", &peer->application_name);
    *last = '\0';
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PostgreSQL connstring: %s", connstring);
    /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    pgdt->pgconn = PQconnectStart((const char *)connstring);
    if (PQsetnonblocking(pgdt->pgconn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: connection failed: %s in upstream \"%V\"", PQerrorMessage(pgdt->pgconn), &peer->name);
        PQfinish(pgdt->pgconn);
        pgdt->pgconn = NULL;
        return NGX_DECLINED;
    }
//    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s connection status:%d", __func__, (int) PQstatus(pgdt->pgconn));
    /* take spot in keepalive connection pool */
    pgscf->active_conns++;
    /* add the file descriptor (fd) into an nginx connection structure */
    int fd = PQsocket(pgdt->pgconn);
    if (fd == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to get connection fd"); goto invalid; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: connection fd:%d", fd);
    if (!(pc->connection = ngx_get_connection(fd, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to get a free nginx connection"); goto invalid; }
    ngx_connection_t *pgxc = pc->connection;
    pgxc->log = pc->log;
    pgxc->log_error = pc->log_error;
    pgxc->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    ngx_event_t *rev = pgxc->read;
    ngx_event_t *wev = pgxc->write;
    rev->log = pc->log;
    wev->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s NGX_USE_RTSIG_EVENT", __func__);
        if (ngx_add_conn(pgxc) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s NGX_USE_CLEAR_EVENT", __func__);
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s NGX_USE_LEVEL_EVENT", __func__);
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
    }
//    pgxc->log->action = "connecting to PostgreSQL database";
    pgdt->state = state_db_connect;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to add nginx connection");
invalid:
    ngx_postgres_upstream_free_connection(pc->connection, pgdt->pgconn, pgscf);
    return NGX_ERROR;
}


static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_postgres_upstream_peer_data_t  *pgdt = data;
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->srv_conf;
    if (pgscf->max_cached) ngx_postgres_keepalive_free_peer(pc, pgdt, state);
    if (pc->connection) {
        ngx_postgres_upstream_free_connection(pc->connection, pgdt->pgconn, pgscf);
        pgdt->pgconn = NULL;
        pc->connection = NULL;
    }
}


ngx_flag_t ngx_postgres_upstream_is_my_peer(const ngx_peer_connection_t *peer) {
    return (peer->get == ngx_postgres_upstream_get_peer);
}


void ngx_postgres_upstream_free_connection(ngx_connection_t *c, PGconn *pgconn, ngx_postgres_upstream_srv_conf_t *pgscf) {
    PQfinish(pgconn);
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
    pgscf->active_conns--;
}
