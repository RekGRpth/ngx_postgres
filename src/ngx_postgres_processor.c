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

#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_util.h"
#include "ngx_postgres_variable.h"

#include <postgresql/server/catalog/pg_type_d.h>


static ngx_int_t ngx_postgres_upstream_connect(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_send_query(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_get_result(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_get_ack(ngx_http_request_t *r);
static ngx_int_t ngx_postgres_upstream_done(ngx_http_request_t *r);


void ngx_postgres_process_events(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    ngx_int_t rc;
    if (!ngx_postgres_upstream_is_my_peer(&u->peer)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: trying to connect to something that is not PostgreSQL database"); goto failed; }
    switch (pgdt->state) {
        case state_db_connect: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_connect");
            rc = ngx_postgres_upstream_connect(r);
        } break;
        case state_db_send_query: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_send_query");
            rc = ngx_postgres_upstream_send_query(r);
        } break;
        case state_db_get_result: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_get_result");
            rc = ngx_postgres_upstream_get_result(r);
        } break;
        case state_db_get_ack: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_get_ack");
            rc = ngx_postgres_upstream_get_ack(r);
        } break;
        case state_db_idle: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state_db_idle, re-using keepalive connection");
            pgdt->state = state_db_send_query;
            rc = ngx_postgres_upstream_send_query(r);
        } break;
        default: {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: unknown state:%d", pgdt->state);
            goto failed;
        }
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_postgres_upstream_finalize_request(r, u, rc);
    } else if (rc == NGX_ERROR) {
        goto failed;
    }
    return;
failed:
    ngx_postgres_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
}


static ngx_int_t ngx_postgres_upstream_connect(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    PostgresPollingStatusType  pgrc = PQconnectPoll(pgdt->pgconn);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: polling while connecting, rc:%d", (int) pgrc);
    if (pgrc == PGRES_POLLING_READING || pgrc == PGRES_POLLING_WRITING) {
        /*
         * Fix for Linux issue found by chaoslawful (via agentzh):
         * "According to the source of libpq (around fe-connect.c:1215), during
         *  the state switch from CONNECTION_STARTED to CONNECTION_MADE, there's
         *  no socket read/write operations (just a plain getsockopt call and a
         *  getsockname call). Therefore, for edge-triggered event model, we
         *  have to call PQconnectPoll one more time (immediately) when we see
         *  CONNECTION_MADE is returned, or we're very likely to wait for a
         *  writable event that has already appeared and will never appear
         *  again :)"
         */
        if (PQstatus(pgdt->pgconn) == CONNECTION_MADE && u->peer.connection->write->ready) {
            pgrc = PQconnectPoll(pgdt->pgconn);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: re-polling while connecting, rc:%d", (int) pgrc);
            if (pgrc == PGRES_POLLING_READING || pgrc == PGRES_POLLING_WRITING) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while connecting, rc:%d", (int) pgrc); return NGX_AGAIN; }
            goto done;
        }
        switch (PQstatus(pgdt->pgconn)) {
            case CONNECTION_NEEDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "waiting for connect"); break;
            case CONNECTION_STARTED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "waiting for connection to be made"); break;
            case CONNECTION_MADE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "connection established"); break;
            case CONNECTION_AWAITING_RESPONSE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "credentials sent, waiting for response"); break;
            case CONNECTION_AUTH_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "authenticated"); break;
            case CONNECTION_SETENV: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "negotiating envinroment"); break;
            case CONNECTION_SSL_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "negotiating SSL"); break;
            default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "unknown state: %d", (int) PQstatus(pgdt->pgconn)); return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while connecting, rc:%d", (int) pgrc);
        return NGX_AGAIN;
    }
done:
    /* remove connection timeout from new connection */
    if (u->peer.connection->write->timer_set) ngx_del_timer(u->peer.connection->write);
    if (pgrc != PGRES_POLLING_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: connection failed: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: connected successfully");
    pgdt->state = state_db_send_query;
    return ngx_postgres_upstream_send_query(r);
}


static ngx_int_t ngx_postgres_upstream_send_query(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    ngx_postgres_loc_conf_t *pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (pgdt->pgscf->prepare) {
        PGresult *res = PQdescribePrepared(pgdt->pgconn, (const char *)pgdt->stmtName);
        if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            PGresult *res = PQprepare(pgdt->pgconn, (const char *)pgdt->stmtName, (const char *)pgdt->command, pgdt->nParams, pgdt->paramTypes);
            if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (PQresultStatus(res) != PGRES_COMMAND_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to prepare: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
            PQclear(res);
        }
        PQclear(res);
        if (!PQsendQueryPrepared(pgdt->pgconn, (const char *)pgdt->stmtName, pgdt->nParams, (const char *const *)pgdt->paramValues, NULL, NULL, pglcf->output_binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send prepared query: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    } else if (!PQsendQueryParams(pgdt->pgconn, (const char *)pgdt->command, pgdt->nParams, pgdt->paramTypes, (const char *const *)pgdt->paramValues, NULL, NULL, pglcf->output_binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send query: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    /* set result timeout */
    ngx_add_timer(u->peer.connection->read, r->upstream->conf->read_timeout);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: query sent successfully");
    pgdt->state = state_db_get_result;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_result(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    /* remove connection timeout from re-used keepalive connection */
    if (u->peer.connection->write->timer_set) ngx_del_timer(u->peer.connection->write);
    if (!PQconsumeInput(pgdt->pgconn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    if (PQisBusy(pgdt->pgconn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while receiving result"); return NGX_AGAIN; }
    PGresult *res = PQgetResult(pgdt->pgconn);
    if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to receive result: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    ExecStatusType pgrc = PQresultStatus(res);
    if ((pgrc != PGRES_COMMAND_OK) && (pgrc != PGRES_TUPLES_OK)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to receive result: %s: %s", PQresStatus(pgrc), PQerrorMessage(pgdt->pgconn));
        PQclear(res);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: result received successfully, cols:%d rows:%d", PQnfields(res), PQntuples(res));
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    pgctx->res = res;
    ngx_int_t rc = ngx_postgres_process_response(r);
    PQclear(res);
    if (rc != NGX_DONE) return rc;
    pgdt->state = state_db_get_ack;
    return ngx_postgres_upstream_get_ack(r);
}


static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r) {
    ngx_postgres_loc_conf_t *pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    pgctx->var_cols = PQnfields(pgctx->res); /* set $postgres_columns */
    pgctx->var_rows = PQntuples(pgctx->res); /* set $postgres_rows */
    if (ngx_strncasecmp((u_char *)PQcmdStatus(pgctx->res), (u_char *)"SELECT", sizeof("SELECT") - 1)) { /* set $postgres_affected */
        char *affected = PQcmdTuples(pgctx->res);
        size_t affected_len = ngx_strlen(affected);
        if (affected_len) pgctx->var_affected = ngx_atoi((u_char *)affected, affected_len);
    }
    if (pglcf->rewrites) { /* process rewrites */
        ngx_postgres_rewrite_conf_t  *pgrcf = pglcf->rewrites->elts;
        for (ngx_uint_t i = 0; i < pglcf->rewrites->nelts; i++) {
            ngx_int_t rc = pgrcf[i].handler(r, &pgrcf[i]);
            if (rc != NGX_DECLINED) {
                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) { pgctx->status = rc; return NGX_DONE; }
                pgctx->status = rc;
                break;
            }
        }
    }
    if (pglcf->variables) { /* set custom variables */
        ngx_postgres_variable_t *pgvar = pglcf->variables->elts;
        ngx_str_t *store = pgctx->variables->elts;
        for (ngx_uint_t i = 0; i < pglcf->variables->nelts; i++) {
            store[i] = ngx_postgres_variable_set_custom(r, pgctx->res, &pgvar[i]);
            if (!store[i].len && pgvar[i].value.required) { pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR; return NGX_DONE; }
        }
    }
    if (pglcf->output_handler) return pglcf->output_handler(r);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_ack(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    if (!PQconsumeInput(pgdt->pgconn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    if (PQisBusy(pgdt->pgconn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while get ack"); return NGX_AGAIN; }
    if (u->peer.connection->read->timer_set) ngx_del_timer(u->peer.connection->read); /* remove result timeout */
    PGresult *res = PQgetResult(pgdt->pgconn);
    if (res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: receiving ACK failed: multiple queries(?)"); PQclear(res); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    pgdt->state = state_db_idle;
    return ngx_postgres_upstream_done(r);
}


static ngx_int_t ngx_postgres_upstream_done(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_ctx_t *pgctx;
    u->headers_in.status_n = NGX_HTTP_OK; /* flag for keepalive */
    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (pgctx->status >= NGX_HTTP_SPECIAL_RESPONSE) ngx_postgres_upstream_finalize_request(r, u, pgctx->status);
    else ngx_postgres_upstream_finalize_request(r, u, NGX_OK);
    return NGX_DONE;
}
