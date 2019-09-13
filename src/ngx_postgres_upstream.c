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

#include "ngx_postgres_keepalive.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);


ngx_int_t ngx_postgres_upstream_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    uscf->peer.init = ngx_postgres_upstream_init_peer;
    ngx_postgres_srv_conf_t *srv_conf = ngx_http_conf_upstream_srv_conf(uscf, ngx_postgres_module);
    if (!uscf->servers || !uscf->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &uscf->host, uscf->file_name, uscf->line); return NGX_ERROR; }
    ngx_postgres_upstream_server_t *server = uscf->servers->elts;
    ngx_uint_t n = 0;
    for (ngx_uint_t i = 0; i < uscf->servers->nelts; i++) n += server[i].naddrs;
    ngx_postgres_upstream_peers_t *peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_upstream_peers_t) + sizeof(ngx_postgres_upstream_peer_t) * (n - 1));
    if (!peers) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    peers->single = (n == 1);
    peers->number = n;
    n = 0;
    for (ngx_uint_t i = 0; i < uscf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < server[i].naddrs; j++) {
            ngx_postgres_upstream_peer_t *peer = &peers->peer[n];
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
    srv_conf->peers = peers;
    srv_conf->active_conns = 0;
    if (srv_conf->max_cached) return ngx_postgres_keepalive_init(cf->pool, srv_conf);
    return NGX_OK;
}


ngx_str_t PQescapeInternal(ngx_pool_t *pool, const u_char *str, size_t len, ngx_flag_t as_ident) {
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


static ngx_int_t ngx_postgres_upstream_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_postgres_upstream_peer_data_t *pgdt = ngx_pcalloc(r->pool, sizeof(ngx_postgres_upstream_peer_data_t));
    if (!pgdt) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_http_upstream_t *u = r->upstream;
    pgdt->upstream = u;
    pgdt->request = r;
    ngx_postgres_srv_conf_t *srv_conf = ngx_http_conf_upstream_srv_conf(uscf, ngx_postgres_module);
    ngx_postgres_loc_conf_t *pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    pgdt->srv_conf = srv_conf;
    if (!(pgdt->statements = ngx_pcalloc(r->pool, srv_conf->max_statements * sizeof(ngx_postgres_statement_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
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
    pgdt->resultFormat = pglcf->output_binary;
    if (query->args.nelts == 1 && !ngx_strncasecmp(query->sql.data, (u_char *)"LISTEN ", sizeof("LISTEN ") - 1)) {
        ngx_postgres_arg_t *arg = query->args.elts;
        ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, arg[0].index);
        if (!value || !value->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no variable value found for listen"); return NGX_ERROR; }
        ngx_str_t channel = PQescapeInternal(r->pool, value->data, value->len, 1);
        if (!channel.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to escape %s: %s", value->data, PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
        query->sql.len = sizeof("LISTEN ") - 1 + channel.len;
        if (!(pgdt->command = ngx_pnalloc(r->pool, query->sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        *ngx_snprintf(pgdt->command, query->sql.len, "LISTEN %V", &channel) = '\0';
        query->sql.data = pgdt->command;
    } else {
        if (!(pgdt->command = ngx_pnalloc(r->pool, query->sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        (void) ngx_cpystrn(pgdt->command, query->sql.data, query->sql.len + 1);
        if (query->args.nelts) {
            ngx_postgres_arg_t *arg = query->args.elts;
            pgdt->nParams = query->args.nelts;
            if (!(pgdt->paramTypes = ngx_pnalloc(r->pool, query->args.nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (!(pgdt->paramValues = ngx_pnalloc(r->pool, query->args.nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            for (ngx_uint_t i = 0; i < query->args.nelts; i++) {
                pgdt->paramTypes[i] = arg[i].oid;
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, arg[i].index);
                if (!value || !value->data) pgdt->paramValues[i] = NULL; else {
                    if (!(pgdt->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                    (void) ngx_cpystrn(pgdt->paramValues[i], value->data, value->len + 1);
                }
            }
        }
    }
    if (srv_conf->max_statements) {
        pgdt->hash = ngx_hash_key(query->sql.data, query->sql.len);
        *ngx_snprintf(pgdt->stmtName, 32, "ngx_%ul", (unsigned long)pgdt->hash) = '\0';
    }
    pgctx->var_query = query->sql; /* set $postgres_query */
    return NGX_OK;
}


static ngx_int_t ngx_postgres_upstream_get_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_postgres_upstream_peer_data_t *pgdt = data;
    pgdt->failed = 0;
    if (pgdt->srv_conf->max_cached && pgdt->srv_conf->single && ngx_postgres_keepalive_get_peer_single(pc, pgdt) != NGX_DECLINED) { /* re-use keepalive peer */
        pgdt->state = pgdt->srv_conf->max_statements ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(pgdt->request);
        return NGX_AGAIN;
    }
    if (pgdt->srv_conf->current > pgdt->srv_conf->peers->number - 1) pgdt->srv_conf->current = 0;
    ngx_postgres_upstream_peer_t *peer = &pgdt->srv_conf->peers->peer[pgdt->srv_conf->current++];
    pgdt->name = peer->name;
    pgdt->sockaddr = *peer->sockaddr;
    pc->name = &pgdt->name;
    pc->sockaddr = &pgdt->sockaddr;
    pc->socklen = peer->socklen;
    pc->cached = 0;
    if (pgdt->srv_conf->max_cached && !pgdt->srv_conf->single && ngx_postgres_keepalive_get_peer_multi(pc, pgdt) != NGX_DECLINED) { /* re-use keepalive peer */
        pgdt->state = pgdt->srv_conf->max_statements ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(pgdt->request);
        return NGX_AGAIN;
    }
    if (pgdt->srv_conf->reject && pgdt->srv_conf->active_conns >= pgdt->srv_conf->max_cached) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0, "postgres: keepalive connection pool is full, rejecting request to upstream \"%V\"", &peer->name);
        pc->connection = ngx_get_connection(0, pc->log); /* a bit hack-ish way to return error response (setup part) */
        return NGX_AGAIN;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PostgreSQL connstring: %s", peer->connstring);
    /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    pgdt->pgconn = PQconnectStart((const char *)peer->connstring);
    if (PQstatus(pgdt->pgconn) == CONNECTION_BAD || PQsetnonblocking(pgdt->pgconn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: connection failed: %s in upstream \"%V\"", PQerrorMessage(pgdt->pgconn), &peer->name);
        PQfinish(pgdt->pgconn);
        pgdt->pgconn = NULL;
        return NGX_DECLINED;
    }
    pgdt->srv_conf->active_conns++; /* take spot in keepalive connection pool */
    int fd = PQsocket(pgdt->pgconn); /* add the file descriptor (fd) into an nginx connection structure */
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
    pgdt->state = state_db_connect;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "postgres: failed to add nginx connection");
invalid:
    ngx_postgres_upstream_free_connection(pc->connection, pgdt->pgconn, pgdt->srv_conf);
    return NGX_ERROR;
}


static void ngx_postgres_upstream_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_postgres_upstream_peer_data_t *pgdt = data;
    if (pgdt->srv_conf->max_cached) ngx_postgres_keepalive_free_peer(pc, pgdt, state);
    if (pc->connection) {
        ngx_postgres_upstream_free_connection(pc->connection, pgdt->pgconn, pgdt->srv_conf);
        pgdt->pgconn = NULL;
        pc->connection = NULL;
    }
}


ngx_flag_t ngx_postgres_upstream_is_my_peer(const ngx_peer_connection_t *peer) {
    return (peer->get == ngx_postgres_upstream_get_peer);
}


void ngx_postgres_upstream_free_connection(ngx_connection_t *c, PGconn *pgconn, ngx_postgres_srv_conf_t *srv_conf) {
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
    srv_conf->active_conns--;
}
