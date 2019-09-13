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

#include <postgresql/server/catalog/pg_type_d.h>

#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_util.h"
#include "ngx_postgres_variable.h"


static ngx_int_t ngx_postgres_upstream_connect(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_send_query(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_get_result(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_get_ack(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_done(ngx_http_request_t *r);


static const char *PostgresPollingStatusType2string(PostgresPollingStatusType status) {
    switch (status) {
        case PGRES_POLLING_FAILED: return "PGRES_POLLING_FAILED";
        case PGRES_POLLING_READING: return "PGRES_POLLING_READING";
        case PGRES_POLLING_WRITING: return "PGRES_POLLING_WRITING";
        case PGRES_POLLING_OK: return "PGRES_POLLING_OK";
        case PGRES_POLLING_ACTIVE: return "PGRES_POLLING_ACTIVE";
        default: return NULL;
    }
    return NULL;
}


static const char *ConnStatusType2string(ConnStatusType status) {
    switch (status) {
        case CONNECTION_OK: return "CONNECTION_OK";
        case CONNECTION_BAD: return "CONNECTION_BAD";
        case CONNECTION_STARTED: return "CONNECTION_STARTED";
        case CONNECTION_MADE: return "CONNECTION_MADE";
        case CONNECTION_AWAITING_RESPONSE: return "CONNECTION_AWAITING_RESPONSE";
        case CONNECTION_AUTH_OK: return "CONNECTION_AUTH_OK";
        case CONNECTION_SETENV: return "CONNECTION_SETENV";
        case CONNECTION_SSL_STARTUP: return "CONNECTION_SSL_STARTUP";
        case CONNECTION_NEEDED: return "CONNECTION_NEEDED";
        case CONNECTION_CHECK_WRITABLE: return "CONNECTION_CHECK_WRITABLE";
        case CONNECTION_CONSUME: return "CONNECTION_CONSUME";
        default: return NULL;
    }
    return NULL;
}


void ngx_postgres_process_events(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    if (!ngx_postgres_upstream_is_my_peer(&u->peer)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: trying to connect to something that is not PostgreSQL database"); goto failed; }
    ngx_postgres_peer_data_t *peer_data = u->peer.data;
    ngx_int_t rc;
    switch (peer_data->state) {
        case state_db_connect: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_connect"); rc = ngx_postgres_upstream_connect(r); break;
        case state_db_send_prepare: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_send_prepare"); rc = ngx_postgres_upstream_send_query(r); break;
        case state_db_send_query: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_send_query"); rc = ngx_postgres_upstream_send_query(r); break;
        case state_db_get_result: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_get_result"); rc = ngx_postgres_upstream_get_result(r); break;
        case state_db_get_ack: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_get_ack"); rc = ngx_postgres_upstream_get_ack(r); break;
        case state_db_idle: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_idle, re-using keepalive connection"); peer_data->state = state_db_send_query; rc = ngx_postgres_upstream_send_query(r); break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: unknown state:%d", peer_data->state); goto failed;
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) ngx_postgres_upstream_finalize_request(r, u, rc);
    else if (rc == NGX_ERROR) goto failed;
    return;
failed:
    ngx_postgres_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
}


static ngx_int_t ngx_postgres_upstream_connect(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_peer_data_t *peer_data = u->peer.data;
    PostgresPollingStatusType poll_status = PQconnectPoll(peer_data->conn);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: polling while connecting, %s", PostgresPollingStatusType2string(poll_status));
    if (poll_status == PGRES_POLLING_READING || poll_status == PGRES_POLLING_WRITING) {
        if (PQstatus(peer_data->conn) == CONNECTION_MADE && u->peer.connection->write->ready) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: re-polling while connecting");
            return ngx_postgres_upstream_connect(r);
        }
        ConnStatusType conn_status;
        switch ((conn_status = PQstatus(peer_data->conn))) {
            case CONNECTION_NEEDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_NEEDED"); break;
            case CONNECTION_STARTED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_STARTED"); break;
            case CONNECTION_MADE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_MADE"); break;
            case CONNECTION_AWAITING_RESPONSE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_AWAITING_RESPONSE"); break;
            case CONNECTION_AUTH_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_AUTH_OK"); break;
            case CONNECTION_SETENV: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_SETENV"); break;
            case CONNECTION_SSL_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "CONNECTION_SSL_STARTUP"); break;
            default: ngx_log_debug1(NGX_LOG_ERR, r->connection->log, 0, "unknown state: %s", ConnStatusType2string(conn_status)); return NGX_ERROR;
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while connecting");
        return NGX_AGAIN;
    }
    if (u->peer.connection->write->timer_set) ngx_del_timer(u->peer.connection->write); /* remove connection timeout from new connection */
    if (poll_status != PGRES_POLLING_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: connection failed: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: connected successfully");
    peer_data->state = peer_data->server_conf->max_statements ? state_db_send_prepare : state_db_send_query;
    return ngx_postgres_upstream_send_query(r);
}


static ngx_int_t ngx_postgres_upstream_send_query(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_peer_data_t *peer_data = u->peer.data;
    if (!PQconsumeInput(peer_data->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
    if (PQisBusy(peer_data->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while send query"); return NGX_AGAIN; }
    for (PGresult *res; (res = PQgetResult(peer_data->conn)); PQclear(res)) if (PQresultStatus(res) != PGRES_COMMAND_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send query: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res)); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
//    ngx_postgres_process_notify(r->connection->log, r->pool, peer_data->conn);
    if (!peer_data->server_conf->max_statements) {
        if (!PQsendQueryParams(peer_data->conn, (const char *)peer_data->command, peer_data->nParams, peer_data->paramTypes, (const char *const *)peer_data->paramValues, NULL, NULL, peer_data->resultFormat)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send query: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: query sent successfully");
    } else switch (peer_data->state) {
        case state_db_send_prepare: {
            ngx_uint_t n;
            ngx_flag_t matched = 0;
            for (n = 0; n < peer_data->server_conf->max_statements && peer_data->statements[n].hash; n++) if (peer_data->statements[n].hash == peer_data->hash) { matched = 1; break; }
            if (!matched) {
                if (n == peer_data->server_conf->max_statements) for (ngx_uint_t i = 0, used = peer_data->statements[0].used; i < peer_data->server_conf->max_statements; i++) if (peer_data->statements[i].used < used) { used = peer_data->statements[i].used; n = i; }
                peer_data->statements[n].hash = peer_data->hash;
                peer_data->statements[n].used++;
                if (!PQsendPrepare(peer_data->conn, (const char *)peer_data->stmtName, (const char *)peer_data->command, peer_data->nParams, peer_data->paramTypes)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send prepare: %s", PQerrorMessage(peer_data->conn)); /*PQclear(res); */return NGX_ERROR; }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: prepare sent successfully");
                peer_data->state = state_db_send_query;
                return NGX_DONE;
            }
            peer_data->state = state_db_send_query;
        } /* Fall through. */
        case state_db_send_query: {
            if (!PQsendQueryPrepared(peer_data->conn, (const char *)peer_data->stmtName, peer_data->nParams, (const char *const *)peer_data->paramValues, NULL, NULL, peer_data->resultFormat)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send prepared query: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: query sent successfully");
        } break;
        default: { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    }
    ngx_add_timer(u->peer.connection->read, r->upstream->conf->read_timeout); /* set result timeout */
    peer_data->state = state_db_get_result;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_result(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_peer_data_t *peer_data = u->peer.data;
    if (u->peer.connection->write->timer_set) ngx_del_timer(u->peer.connection->write); /* remove connection timeout from re-used keepalive connection */
    if (!PQconsumeInput(peer_data->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
    if (PQisBusy(peer_data->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while receiving result"); return NGX_AGAIN; }
    PGresult *res = PQgetResult(peer_data->conn);
    if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to receive result: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
    if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to receive result: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res)); PQclear(res); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: result received successfully, cols:%d rows:%d", PQnfields(res), PQntuples(res));
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    context->res = res;
    ngx_int_t rc = ngx_postgres_process_response(r);
    PQclear(res);
//    ngx_postgres_process_notify(r->connection->log, r->pool, peer_data->conn);
    if (rc != NGX_DONE) return rc;
    peer_data->state = state_db_get_ack;
    return ngx_postgres_upstream_get_ack(r);
}


static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r) {
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    context->var_cols = PQnfields(context->res); /* set $postgres_columns */
    context->var_rows = PQntuples(context->res); /* set $postgres_rows */
    if (ngx_strncasecmp((u_char *)PQcmdStatus(context->res), (u_char *)"SELECT", sizeof("SELECT") - 1)) { /* set $postgres_affected */
        char *affected = PQcmdTuples(context->res);
        size_t affected_len = ngx_strlen(affected);
        if (affected_len) context->var_affected = ngx_atoi((u_char *)affected, affected_len);
    }
    if (location_conf->rewrite_conf) { /* process rewrites */
        ngx_postgres_rewrite_conf_t *rewrite_conf = location_conf->rewrite_conf->elts;
        for (ngx_uint_t i = 0; i < location_conf->rewrite_conf->nelts; i++) {
            ngx_int_t rc = rewrite_conf[i].handler(r, &rewrite_conf[i]);
            if (rc != NGX_DECLINED) {
                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { context->status = rc; return NGX_DONE; }
                context->status = rc;
                break;
            }
        }
    }
    if (location_conf->variables) { /* set custom variables */
        ngx_postgres_variable_t *pgvar = location_conf->variables->elts;
        ngx_str_t *store = context->variables->elts;
        for (ngx_uint_t i = 0; i < location_conf->variables->nelts; i++) {
            store[i] = ngx_postgres_variable_set_custom(r, &pgvar[i]);
            if (!store[i].len && pgvar[i].value.required) { context->status = NGX_HTTP_INTERNAL_SERVER_ERROR; ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_DONE; }
        }
    }
    if (location_conf->output_handler) return location_conf->output_handler(r);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_ack(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_peer_data_t *peer_data = u->peer.data;
    if (!PQconsumeInput(peer_data->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(peer_data->conn)); return NGX_ERROR; }
    if (PQisBusy(peer_data->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while get ack"); return NGX_AGAIN; }
    if (u->peer.connection->read->timer_set) ngx_del_timer(u->peer.connection->read); /* remove result timeout */
    PGresult *res = PQgetResult(peer_data->conn);
    if (res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: receiving ACK failed: multiple queries(?)"); PQclear(res); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
//    ngx_postgres_process_notify(r->connection->log, r->pool, peer_data->conn);
    peer_data->state = state_db_idle;
    return ngx_postgres_upstream_done(r);
}


static ngx_int_t ngx_postgres_upstream_done(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_context_t *context;
    u->headers_in.status_n = NGX_HTTP_OK; /* flag for keepalive */
    context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (context->status >= NGX_HTTP_SPECIAL_RESPONSE) ngx_postgres_upstream_finalize_request(r, u, context->status);
    else ngx_postgres_upstream_finalize_request(r, u, NGX_OK);
    return NGX_DONE;
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
                if (!channel.len) { ngx_log_error(NGX_LOG_ERR, log, 0, "postgres: failed to escape %V: %s", id, PQerrorMessage(conn)); return; }
                u_char *command = ngx_pnalloc(pool, sizeof("UNLISTEN ") - 1 + channel.len + 1);
                if (!command) { ngx_log_error(NGX_LOG_ERR, log, 0, "%s:%d", __FILE__, __LINE__); return; }
                *ngx_snprintf(command, sizeof("UNLISTEN ") - 1 + channel.len + 1, "UNLISTEN %V", &channel) = '\0';
                if (!PQsendQuery(conn, (const char *)command)) { ngx_log_error(NGX_LOG_ERR, log, 0, "postgres: failed to send unlisten: %s", PQerrorMessage(conn)); return; }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "postgres: unlisten sent successfully");
            } return;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "postgres notify ok"); return;
            default: ngx_log_error(NGX_LOG_ERR, log, 0, "postgres notify unknown"); return;
        }
    }
}
