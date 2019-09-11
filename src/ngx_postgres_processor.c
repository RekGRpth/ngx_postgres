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
static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r, PGresult *res);
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
//            r->connection->log->action = "sending query to PostgreSQL database";
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
    ngx_connection_t *pgxc = u->peer.connection;
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
        if (PQstatus(pgdt->pgconn) == CONNECTION_MADE && pgxc->write->ready) {
            pgrc = PQconnectPoll(pgdt->pgconn);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: re-polling while connecting, rc:%d", (int) pgrc);
            if (pgrc == PGRES_POLLING_READING || pgrc == PGRES_POLLING_WRITING) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while connecting, rc:%d", (int) pgrc); return NGX_AGAIN; }
            goto done;
        }
        switch (PQstatus(pgdt->pgconn)) {
            case CONNECTION_NEEDED: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (waiting for connect()))", __func__); break;
            case CONNECTION_STARTED: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (waiting for connection to be made)", __func__); break;
            case CONNECTION_MADE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (connection established)", __func__); break;
            case CONNECTION_AWAITING_RESPONSE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (credentials sent, waiting for response)", __func__); break;
            case CONNECTION_AUTH_OK: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (authenticated)", __func__); break;
            case CONNECTION_SETENV: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (negotiating envinroment)", __func__); break;
            case CONNECTION_SSL_STARTUP: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (negotiating SSL)", __func__); break;
            default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s connecting (unknown state:%d)", __func__, (int) PQstatus(pgdt->pgconn)); return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: busy while connecting, rc:%d", (int) pgrc);
        return NGX_AGAIN;
    }
done:
    /* remove connection timeout from new connection */
    if (pgxc->write->timer_set) ngx_del_timer(pgxc->write);
    if (pgrc != PGRES_POLLING_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: connection failed: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: connected successfully");
//    r->connection->log->action = "sending query to PostgreSQL database";
    pgdt->state = state_db_send_query;
    return ngx_postgres_upstream_send_query(r);
}


static ngx_int_t ngx_postgres_upstream_send_query(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_connection_t *pgxc = u->peer.connection;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    ngx_postgres_loc_conf_t *pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (pgdt->srv_conf->prepare) {
        u_char stmtName[32];
        ngx_uint_t hash = ngx_hash_key(pgdt->command, pgdt->command_len);
        *ngx_snprintf(stmtName, 32, "ngx_%ul", (unsigned long)hash) = '\0';
        PGresult *res = PQdescribePrepared(pgdt->pgconn, (const char *)stmtName);
        if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            PGresult *res = PQprepare(pgdt->pgconn, (const char *)stmtName, (const char *)pgdt->command, pgdt->nParams, pgdt->paramTypes);
            if (!res) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (PQresultStatus(res) != PGRES_COMMAND_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to prepare: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
            PQclear(res);
        }
        PQclear(res);
        if (!PQsendQueryPrepared(pgdt->pgconn, (const char *)stmtName, pgdt->nParams, (const char *const *)pgdt->paramValues, NULL, NULL, pglcf->output_binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send prepared query: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    } else if (!PQsendQueryParams(pgdt->pgconn, (const char *)pgdt->command, pgdt->nParams, pgdt->paramTypes, (const char *const *)pgdt->paramValues, NULL, NULL, pglcf->output_binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: failed to send query: %s", PQerrorMessage(pgdt->pgconn)); return NGX_ERROR; }
    /* set result timeout */
    ngx_add_timer(pgxc->read, r->upstream->conf->read_timeout);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "postgres: query sent successfully");
//    r->connection->log->action = "waiting for result from PostgreSQL database";
    pgdt->state = state_db_get_result;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_result(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_connection_t *pgxc = u->peer.connection;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    /* remove connection timeout from re-used keepalive connection */
    if (pgxc->write->timer_set) ngx_del_timer(pgxc->write);
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
//    r->connection->log->action = "processing result from PostgreSQL database";
    ngx_int_t rc = ngx_postgres_process_response(r, res);
    PQclear(res);
    if (rc != NGX_DONE) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning rc:%d", __func__, (int) rc); return rc; }
//    r->connection->log->action = "waiting for ACK from PostgreSQL database";
    pgdt->state = state_db_get_ack;
    return ngx_postgres_upstream_get_ack(r);
}


static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r, PGresult *res) {
    ngx_postgres_loc_conf_t      *pglcf;
    ngx_postgres_ctx_t           *pgctx;
    ngx_postgres_rewrite_conf_t  *pgrcf;
    ngx_postgres_variable_t      *pgvar;
    ngx_str_t                    *store;
    char                         *affected;
    size_t                        affected_len;
    ngx_uint_t                    i;
    ngx_int_t                     rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s entering", __func__);

    pglcf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    /* set $postgres_columns */
    pgctx->var_cols = PQnfields(res);

    /* set $postgres_rows */
    pgctx->var_rows = PQntuples(res);

    pgctx->res = res;

    /* set $postgres_affected */
    if (ngx_strncmp(PQcmdStatus(res), "SELECT", sizeof("SELECT") - 1)) {
        affected = PQcmdTuples(res);
        affected_len = ngx_strlen(affected);
        if (affected_len) {
            pgctx->var_affected = ngx_atoi((u_char *) affected, affected_len);
        }
    }

    if (pglcf->rewrites) {
        /* process rewrites */
        pgrcf = pglcf->rewrites->elts;
        for (i = 0; i < pglcf->rewrites->nelts; i++) {
            rc = pgrcf[i].handler(r, &pgrcf[i]);
            if (rc != NGX_DECLINED) {
                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning NGX_DONE, status %d", __func__, (int) rc);
                    pgctx->status = rc;
                    pgctx->res = NULL;
                    return NGX_DONE;
                }

                pgctx->status = rc;
                break;
            }
        }
    }

    pgctx->res = NULL;

    if (pglcf->variables) {
        /* set custom variables */
        pgvar = pglcf->variables->elts;
        store = pgctx->variables->elts;

        for (i = 0; i < pglcf->variables->nelts; i++) {
            store[i] = ngx_postgres_variable_set_custom(r, res, &pgvar[i]);
            if ((store[i].len == 0) && (pgvar[i].value.required)) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning NGX_DONE, status NGX_HTTP_INTERNAL_SERVER_ERROR", __func__);
                pgctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_DONE;
            }
        }
    }

    if (pglcf->output_handler) {
        /* generate output */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning", __func__);
        return pglcf->output_handler(r, res);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning NGX_DONE", __func__);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_upstream_get_ack(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_connection_t *pgxc = u->peer.connection;
    ngx_postgres_upstream_peer_data_t *pgdt = u->peer.data;
    PGresult  *res;
    if (!PQconsumeInput(pgdt->pgconn)) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning NGX_ERROR", __func__); return NGX_ERROR; }
    if (PQisBusy(pgdt->pgconn)) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s returning NGX_AGAIN", __func__); return NGX_AGAIN; }
    /* remove result timeout */
    if (pgxc->read->timer_set) ngx_del_timer(pgxc->read);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s receiving ACK (ready for next query)", __func__);
    if ((res = PQgetResult(pgdt->pgconn)) != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "postgres: receiving ACK failed: multiple queries(?)");
        PQclear(res);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
//    r->connection->log->action = "being idle on PostgreSQL database";
    pgdt->state = state_db_idle;
    return ngx_postgres_upstream_done(r);
}


static ngx_int_t ngx_postgres_upstream_done(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_ctx_t *pgctx;
    /* flag for keepalive */
    u->headers_in.status_n = NGX_HTTP_OK;
    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (pgctx->status >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_postgres_upstream_finalize_request(r, u, pgctx->status);
    } else {
        ngx_postgres_upstream_finalize_request(r, u, NGX_OK);
    }
    return NGX_DONE;
}
