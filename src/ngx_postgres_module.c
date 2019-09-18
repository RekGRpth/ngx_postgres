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

#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_rewrite.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


#define NGX_CONF_TAKE34  (NGX_CONF_TAKE3|NGX_CONF_TAKE4)


static ngx_http_variable_t ngx_postgres_module_variables[] = {

    { ngx_string("postgres_columns"), NULL,
      ngx_postgres_variable_columns, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("postgres_rows"), NULL,
      ngx_postgres_variable_rows, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("postgres_affected"), NULL,
      ngx_postgres_variable_affected, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("postgres_query"), NULL,
      ngx_postgres_variable_query, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

ngx_conf_bitmask_t ngx_postgres_http_methods[] = {
   { ngx_string("GET"),       NGX_HTTP_GET },
   { ngx_string("HEAD"),      NGX_HTTP_HEAD },
   { ngx_string("POST"),      NGX_HTTP_POST },
   { ngx_string("PUT"),       NGX_HTTP_PUT },
   { ngx_string("DELETE"),    NGX_HTTP_DELETE },
   { ngx_string("MKCOL"),     NGX_HTTP_MKCOL },
   { ngx_string("COPY"),      NGX_HTTP_COPY },
   { ngx_string("MOVE"),      NGX_HTTP_MOVE },
   { ngx_string("OPTIONS"),   NGX_HTTP_OPTIONS },
   { ngx_string("PROPFIND"),  NGX_HTTP_PROPFIND },
   { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
   { ngx_string("LOCK"),      NGX_HTTP_LOCK },
   { ngx_string("UNLOCK"),    NGX_HTTP_UNLOCK },
   { ngx_string("PATCH"),     NGX_HTTP_PATCH },
   { ngx_null_string, 0 }
};

#define IDOID 9999

ngx_conf_enum_t ngx_postgres_oids[] = {
    { ngx_string("IDOID"),  IDOID },
    { ngx_string("BOOLOID"),  BOOLOID },
    { ngx_string("BYTEAOID"),  BYTEAOID },
    { ngx_string("CHAROID"),  CHAROID },
    { ngx_string("NAMEOID"),  NAMEOID },
    { ngx_string("INT8OID"),  INT8OID },
    { ngx_string("INT2OID"),  INT2OID },
    { ngx_string("INT2VECTOROID"),  INT2VECTOROID },
    { ngx_string("INT4OID"),  INT4OID },
    { ngx_string("REGPROCOID"),  REGPROCOID },
    { ngx_string("TEXTOID"),  TEXTOID },
    { ngx_string("OIDOID"),  OIDOID },
    { ngx_string("TIDOID"),  TIDOID },
    { ngx_string("XIDOID"),  XIDOID },
    { ngx_string("CIDOID"),  CIDOID },
    { ngx_string("OIDVECTOROID"),  OIDVECTOROID },
    { ngx_string("JSONOID"),  JSONOID },
    { ngx_string("XMLOID"),  XMLOID },
    { ngx_string("XMLARRAYOID"),  XMLARRAYOID },
    { ngx_string("JSONARRAYOID"),  JSONARRAYOID },
    { ngx_string("PGNODETREEOID"),  PGNODETREEOID },
    { ngx_string("PGNDISTINCTOID"),  PGNDISTINCTOID },
    { ngx_string("PGDEPENDENCIESOID"),  PGDEPENDENCIESOID },
    { ngx_string("PGDDLCOMMANDOID"),  PGDDLCOMMANDOID },
    { ngx_string("SMGROID"),  SMGROID },
    { ngx_string("POINTOID"),  POINTOID },
    { ngx_string("LSEGOID"),  LSEGOID },
    { ngx_string("PATHOID"),  PATHOID },
    { ngx_string("BOXOID"),  BOXOID },
    { ngx_string("POLYGONOID"),  POLYGONOID },
    { ngx_string("LINEOID"),  LINEOID },
    { ngx_string("LINEARRAYOID"),  LINEARRAYOID },
    { ngx_string("FLOAT4OID"),  FLOAT4OID },
    { ngx_string("FLOAT8OID"),  FLOAT8OID },
    { ngx_string("ABSTIMEOID"),  ABSTIMEOID },
    { ngx_string("RELTIMEOID"),  RELTIMEOID },
    { ngx_string("TINTERVALOID"),  TINTERVALOID },
    { ngx_string("UNKNOWNOID"),  UNKNOWNOID },
    { ngx_string("CIRCLEOID"),  CIRCLEOID },
    { ngx_string("CIRCLEARRAYOID"),  CIRCLEARRAYOID },
    { ngx_string("CASHOID"),  CASHOID },
    { ngx_string("MONEYARRAYOID"),  MONEYARRAYOID },
    { ngx_string("MACADDROID"),  MACADDROID },
    { ngx_string("INETOID"),  INETOID },
    { ngx_string("CIDROID"),  CIDROID },
    { ngx_string("MACADDR8OID"),  MACADDR8OID },
    { ngx_string("BOOLARRAYOID"),  BOOLARRAYOID },
    { ngx_string("BYTEAARRAYOID"),  BYTEAARRAYOID },
    { ngx_string("CHARARRAYOID"),  CHARARRAYOID },
    { ngx_string("NAMEARRAYOID"),  NAMEARRAYOID },
    { ngx_string("INT2ARRAYOID"),  INT2ARRAYOID },
    { ngx_string("INT2VECTORARRAYOID"),  INT2VECTORARRAYOID },
    { ngx_string("INT4ARRAYOID"),  INT4ARRAYOID },
    { ngx_string("REGPROCARRAYOID"),  REGPROCARRAYOID },
    { ngx_string("TEXTARRAYOID"),  TEXTARRAYOID },
    { ngx_string("OIDARRAYOID"),  OIDARRAYOID },
    { ngx_string("TIDARRAYOID"),  TIDARRAYOID },
    { ngx_string("XIDARRAYOID"),  XIDARRAYOID },
    { ngx_string("CIDARRAYOID"),  CIDARRAYOID },
    { ngx_string("OIDVECTORARRAYOID"),  OIDVECTORARRAYOID },
    { ngx_string("BPCHARARRAYOID"),  BPCHARARRAYOID },
    { ngx_string("VARCHARARRAYOID"),  VARCHARARRAYOID },
    { ngx_string("INT8ARRAYOID"),  INT8ARRAYOID },
    { ngx_string("POINTARRAYOID"),  POINTARRAYOID },
    { ngx_string("LSEGARRAYOID"),  LSEGARRAYOID },
    { ngx_string("PATHARRAYOID"),  PATHARRAYOID },
    { ngx_string("BOXARRAYOID"),  BOXARRAYOID },
    { ngx_string("FLOAT4ARRAYOID"),  FLOAT4ARRAYOID },
    { ngx_string("FLOAT8ARRAYOID"),  FLOAT8ARRAYOID },
    { ngx_string("ABSTIMEARRAYOID"),  ABSTIMEARRAYOID },
    { ngx_string("RELTIMEARRAYOID"),  RELTIMEARRAYOID },
    { ngx_string("TINTERVALARRAYOID"),  TINTERVALARRAYOID },
    { ngx_string("POLYGONARRAYOID"),  POLYGONARRAYOID },
    { ngx_string("ACLITEMOID"),  ACLITEMOID },
    { ngx_string("ACLITEMARRAYOID"),  ACLITEMARRAYOID },
    { ngx_string("MACADDRARRAYOID"),  MACADDRARRAYOID },
    { ngx_string("MACADDR8ARRAYOID"),  MACADDR8ARRAYOID },
    { ngx_string("INETARRAYOID"),  INETARRAYOID },
    { ngx_string("CIDRARRAYOID"),  CIDRARRAYOID },
    { ngx_string("CSTRINGARRAYOID"),  CSTRINGARRAYOID },
    { ngx_string("BPCHAROID"),  BPCHAROID },
    { ngx_string("VARCHAROID"),  VARCHAROID },
    { ngx_string("DATEOID"),  DATEOID },
    { ngx_string("TIMEOID"),  TIMEOID },
    { ngx_string("TIMESTAMPOID"),  TIMESTAMPOID },
    { ngx_string("TIMESTAMPARRAYOID"),  TIMESTAMPARRAYOID },
    { ngx_string("DATEARRAYOID"),  DATEARRAYOID },
    { ngx_string("TIMEARRAYOID"),  TIMEARRAYOID },
    { ngx_string("TIMESTAMPTZOID"),  TIMESTAMPTZOID },
    { ngx_string("TIMESTAMPTZARRAYOID"),  TIMESTAMPTZARRAYOID },
    { ngx_string("INTERVALOID"),  INTERVALOID },
    { ngx_string("INTERVALARRAYOID"),  INTERVALARRAYOID },
    { ngx_string("NUMERICARRAYOID"),  NUMERICARRAYOID },
    { ngx_string("TIMETZOID"),  TIMETZOID },
    { ngx_string("TIMETZARRAYOID"),  TIMETZARRAYOID },
    { ngx_string("BITOID"),  BITOID },
    { ngx_string("BITARRAYOID"),  BITARRAYOID },
    { ngx_string("VARBITOID"),  VARBITOID },
    { ngx_string("VARBITARRAYOID"),  VARBITARRAYOID },
    { ngx_string("NUMERICOID"),  NUMERICOID },
    { ngx_string("REFCURSOROID"),  REFCURSOROID },
    { ngx_string("REFCURSORARRAYOID"),  REFCURSORARRAYOID },
    { ngx_string("REGPROCEDUREOID"),  REGPROCEDUREOID },
    { ngx_string("REGOPEROID"),  REGOPEROID },
    { ngx_string("REGOPERATOROID"),  REGOPERATOROID },
    { ngx_string("REGCLASSOID"),  REGCLASSOID },
    { ngx_string("REGTYPEOID"),  REGTYPEOID },
    { ngx_string("REGROLEOID"),  REGROLEOID },
    { ngx_string("REGNAMESPACEOID"),  REGNAMESPACEOID },
    { ngx_string("REGPROCEDUREARRAYOID"),  REGPROCEDUREARRAYOID },
    { ngx_string("REGOPERARRAYOID"),  REGOPERARRAYOID },
    { ngx_string("REGOPERATORARRAYOID"),  REGOPERATORARRAYOID },
    { ngx_string("REGCLASSARRAYOID"),  REGCLASSARRAYOID },
    { ngx_string("REGTYPEARRAYOID"),  REGTYPEARRAYOID },
    { ngx_string("REGROLEARRAYOID"),  REGROLEARRAYOID },
    { ngx_string("REGNAMESPACEARRAYOID"),  REGNAMESPACEARRAYOID },
    { ngx_string("UUIDOID"),  UUIDOID },
    { ngx_string("UUIDARRAYOID"),  UUIDARRAYOID },
    { ngx_string("LSNOID"),  LSNOID },
    { ngx_string("PG_LSNARRAYOID"),  PG_LSNARRAYOID },
    { ngx_string("TSVECTOROID"),  TSVECTOROID },
    { ngx_string("GTSVECTOROID"),  GTSVECTOROID },
    { ngx_string("TSQUERYOID"),  TSQUERYOID },
    { ngx_string("REGCONFIGOID"),  REGCONFIGOID },
    { ngx_string("REGDICTIONARYOID"),  REGDICTIONARYOID },
    { ngx_string("TSVECTORARRAYOID"),  TSVECTORARRAYOID },
    { ngx_string("GTSVECTORARRAYOID"),  GTSVECTORARRAYOID },
    { ngx_string("TSQUERYARRAYOID"),  TSQUERYARRAYOID },
    { ngx_string("REGCONFIGARRAYOID"),  REGCONFIGARRAYOID },
    { ngx_string("REGDICTIONARYARRAYOID"),  REGDICTIONARYARRAYOID },
    { ngx_string("JSONBOID"),  JSONBOID },
    { ngx_string("JSONBARRAYOID"),  JSONBARRAYOID },
    { ngx_string("TXID_SNAPSHOTOID"),  TXID_SNAPSHOTOID },
    { ngx_string("TXID_SNAPSHOTARRAYOID"),  TXID_SNAPSHOTARRAYOID },
    { ngx_string("INT4RANGEOID"),  INT4RANGEOID },
    { ngx_string("INT4RANGEARRAYOID"),  INT4RANGEARRAYOID },
    { ngx_string("NUMRANGEOID"),  NUMRANGEOID },
    { ngx_string("NUMRANGEARRAYOID"),  NUMRANGEARRAYOID },
    { ngx_string("TSRANGEOID"),  TSRANGEOID },
    { ngx_string("TSRANGEARRAYOID"),  TSRANGEARRAYOID },
    { ngx_string("TSTZRANGEOID"),  TSTZRANGEOID },
    { ngx_string("TSTZRANGEARRAYOID"),  TSTZRANGEARRAYOID },
    { ngx_string("DATERANGEOID"),  DATERANGEOID },
    { ngx_string("DATERANGEARRAYOID"),  DATERANGEARRAYOID },
    { ngx_string("INT8RANGEOID"),  INT8RANGEOID },
    { ngx_string("INT8RANGEARRAYOID"),  INT8RANGEARRAYOID },
    { ngx_string("RECORDOID"),  RECORDOID },
    { ngx_string("RECORDARRAYOID"),  RECORDARRAYOID },
    { ngx_string("CSTRINGOID"),  CSTRINGOID },
    { ngx_string("ANYOID"),  ANYOID },
    { ngx_string("ANYARRAYOID"),  ANYARRAYOID },
    { ngx_string("VOIDOID"),  VOIDOID },
    { ngx_string("TRIGGEROID"),  TRIGGEROID },
    { ngx_string("EVTTRIGGEROID"),  EVTTRIGGEROID },
    { ngx_string("LANGUAGE_HANDLEROID"),  LANGUAGE_HANDLEROID },
    { ngx_string("INTERNALOID"),  INTERNALOID },
    { ngx_string("OPAQUEOID"),  OPAQUEOID },
    { ngx_string("ANYELEMENTOID"),  ANYELEMENTOID },
    { ngx_string("ANYNONARRAYOID"),  ANYNONARRAYOID },
    { ngx_string("ANYENUMOID"),  ANYENUMOID },
    { ngx_string("FDW_HANDLEROID"),  FDW_HANDLEROID },
    { ngx_string("INDEX_AM_HANDLEROID"),  INDEX_AM_HANDLEROID },
    { ngx_string("TSM_HANDLEROID"),  TSM_HANDLEROID },
    { ngx_string("ANYRANGEOID"),  ANYRANGEOID },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_mode_options[] = {
    { ngx_string("multi"),  0 },
    { ngx_string("single"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_overflow_options[] = {
    { ngx_string("ignore"), 0 },
    { ngx_string("reject"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_prepare_options[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_requirement_options[] = {
    { ngx_string("optional"), 0 },
    { ngx_string("required"), 1 },
    { ngx_null_string, 0 }
};

struct ngx_postgres_rewrite_enum_t {
    ngx_str_t                           name;
    ngx_uint_t                          key;
    ngx_postgres_rewrite_handler_pt     handler;
} ngx_postgres_rewrite_handlers[] = {
    { ngx_string("no_changes"), 0, ngx_postgres_rewrite_changes },
    { ngx_string("changes"),    1, ngx_postgres_rewrite_changes },
    { ngx_string("no_rows"),    2, ngx_postgres_rewrite_rows },
    { ngx_string("rows"),       3, ngx_postgres_rewrite_rows },
    { ngx_string("no_errors"),  4, ngx_postgres_rewrite_valid },
    { ngx_string("errors"),     5, ngx_postgres_rewrite_valid },
    { ngx_null_string, 0, NULL }
};

struct ngx_postgres_output_enum_t {
    ngx_str_t                           name;
    unsigned                            binary:1;
    ngx_postgres_output_handler_pt      handler;
} ngx_postgres_output_handlers[] = {
    { ngx_string("none"),         0, NULL },
    { ngx_string("text") ,        0, ngx_postgres_output_text },
    { ngx_string("value"),        0, ngx_postgres_output_value },
    { ngx_string("binary"),       1, ngx_postgres_output_value },
    { ngx_string("json"),         0, ngx_postgres_output_json },
    { ngx_null_string, 0, NULL }
};


static ngx_int_t ngx_postgres_add_variables(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_postgres_module_variables; v->name.len; v++) {
        ngx_http_variable_t *variable = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!variable) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        variable->get_handler = v->get_handler;
        variable->data = v->data;
    }
    return NGX_OK;
}


static void ngx_postgres_server_conf_cleanup(void *data) {
    ngx_postgres_server_conf_t *server_conf = data;
    if (!server_conf->busy.prev) return; /* ngx_queue_empty is broken when used on unitialized queue */
    server_conf->max_save = 0; /* just to be on the safe-side */
    while (!ngx_queue_empty(&server_conf->busy)) {
        ngx_queue_t *queue = ngx_queue_head(&server_conf->busy);
        ngx_queue_remove(queue);
        ngx_postgres_save_t *save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_postgres_free_connection(save->connection, &save->common);
    }
}


static void *ngx_postgres_create_server_conf(ngx_conf_t *cf) {
    ngx_postgres_server_conf_t *server_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_server_conf_t));
    if (!server_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NULL; }
    /* enable keepalive (single) by default */
    server_conf->max_save = 10;
    server_conf->single = 1;
    server_conf->prepare = 1;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NULL; }
    cln->handler = ngx_postgres_server_conf_cleanup;
    cln->data = server_conf;
    return server_conf;
}


static void *ngx_postgres_create_location_conf(ngx_conf_t *cf) {
    ngx_postgres_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_location_conf_t));
    if (!location_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NULL; }
    location_conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->rewrite_conf = NGX_CONF_UNSET_PTR;
    location_conf->handler = NGX_CONF_UNSET_PTR;
    location_conf->variables = NGX_CONF_UNSET_PTR;
    /* the hardcoded values */
    location_conf->upstream.cyclic_temp_file = 0;
    location_conf->upstream.buffering = 1;
    location_conf->upstream.ignore_client_abort = 1;
    location_conf->upstream.send_lowat = 0;
    location_conf->upstream.bufs.num = 0;
    location_conf->upstream.busy_buffers_size = 0;
    location_conf->upstream.max_temp_file_size = 0;
    location_conf->upstream.temp_file_write_size = 0;
    location_conf->upstream.intercept_errors = 1;
    location_conf->upstream.intercept_404 = 1;
    location_conf->upstream.pass_request_headers = 0;
    location_conf->upstream.pass_request_body = 0;
    return location_conf;
}


static char *ngx_postgres_merge_location_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_postgres_location_conf_t *prev = parent;
    ngx_postgres_location_conf_t *conf = child;
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    if (!conf->upstream.upstream && !conf->upstream_cv) {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->upstream_cv = prev->upstream_cv;
    }
    if (!conf->query && !conf->methods) {
        conf->methods_set = prev->methods_set;
        conf->methods = prev->methods;
        conf->query = prev->query;
    }
    ngx_conf_merge_ptr_value(conf->rewrite_conf, prev->rewrite_conf, NULL);
    if (conf->handler == NGX_CONF_UNSET_PTR) {
        if (prev->handler == NGX_CONF_UNSET_PTR) { /* default */
            conf->handler = NULL;
            conf->binary = 0;
        } else { /* merge */
            conf->handler = prev->handler;
            conf->binary = prev->binary;
        }
    }
    ngx_conf_merge_ptr_value(conf->variables, prev->variables, NULL);
    return NGX_CONF_OK;
}


static ngx_int_t ngx_postgres_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    upstream_srv_conf->peer.init = ngx_postgres_peer_init;
    ngx_postgres_server_conf_t *server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    if (!upstream_srv_conf->servers || !upstream_srv_conf->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &upstream_srv_conf->host, upstream_srv_conf->file_name, upstream_srv_conf->line); return NGX_ERROR; }
    ngx_postgres_server_t *server = upstream_srv_conf->servers->elts;
    ngx_uint_t n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) n += server[i].naddrs;
    ngx_postgres_peers_t *peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_peers_t) + sizeof(ngx_postgres_peer_t) * (n - 1));
    if (!peers) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    peers->single = (n == 1);
    peers->max_peer = n;
    n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < server[i].naddrs; j++) {
            ngx_postgres_peer_t *peer = &peers->peer[n];
            peer->sockaddr = server[i].addrs[j].sockaddr;
            peer->socklen = server[i].addrs[j].socklen;
            peer->name = &server[i].addrs[j].name;
            if (!(peer->host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            if (!(peer->host.len = ngx_sock_ntop(peer->sockaddr, peer->socklen, peer->host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            size_t len = server[i].family == AF_UNIX ? sizeof("host=%s") - 1 - 1 + peer->host.len - 5 : sizeof("hostaddr=%V") - 1 - 1 + peer->host.len;
            len += sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1;
            if (server[i].dbname.len) len += sizeof(" dbname=%V") - 1 - 1 + server[i].dbname.len;
            if (server[i].user.len) len += sizeof(" user=%V") - 1 - 1 + server[i].user.len;
            if (server[i].password.len) len += sizeof(" password=%V") - 1 - 1 + server[i].password.len;
            if (server[i].application_name.len) len += sizeof(" application_name=%V") - 1 - 1 + server[i].application_name.len;
            if (!(peer->connstring = ngx_pnalloc(cf->pool, len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
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
    server_conf->save = 0;
    if (server_conf->max_save) return ngx_postgres_init(cf->pool, server_conf);
    return NGX_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { /* Based on: ngx_http_upstream.c/ngx_http_upstream_server Copyright (C) Igor Sysoev */
    ngx_http_upstream_srv_conf_t *upstream_srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (!upstream_srv_conf->servers && !(upstream_srv_conf->servers = ngx_array_create(cf->pool, 4, sizeof(ngx_postgres_server_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_postgres_server_t *server = ngx_array_push(upstream_srv_conf->servers);
    if (!server) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_memzero(server, sizeof(ngx_postgres_server_t));
    /* parse the first name:port argument */
    ngx_url_t u;
    ngx_memzero(&u, sizeof(ngx_url_t));
    ngx_str_t *value = cf->args->elts;
    u.url = value[1];
    u.default_port = 5432; /* PostgreSQL default */
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s in upstream \"%V\"", u.err, &u.url);
        else ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__);
        return NGX_CONF_ERROR;
    }
    server->addrs = u.addrs;
    server->naddrs = u.naddrs;
    server->port = u.family == AF_UNIX ? u.default_port : u.port;
    server->family = u.family;
    /* parse various options */
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (!ngx_strncmp(value[i].data, "port=", sizeof("port=") - 1)) {
            value[i].len = value[i].len - (sizeof("port=") - 1);
            value[i].data = &value[i].data[sizeof("port=") - 1];
            ngx_int_t n = ngx_atoi(value[i].data, value[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"port\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            server->port = (ngx_uint_t) n;
        } else if (!ngx_strncmp(value[i].data, "dbname=", sizeof("dbname=") - 1)) {
            value[i].len = value[i].len - (sizeof("dbname=") - 1);
            if (!(server->dbname.len = value[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"dbname\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            value[i].data = &value[i].data[sizeof("dbname=") - 1];
            server->dbname.data = value[i].data;
        } else if (!ngx_strncmp(value[i].data, "user=", sizeof("user=") - 1)) {
            value[i].len = value[i].len - (sizeof("user=") - 1);
            if (!(server->user.len = value[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"user\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            value[i].data = &value[i].data[sizeof("user=") - 1];
            server->user.data = value[i].data;
        } else if (!ngx_strncmp(value[i].data, "password=", sizeof("password=") - 1)) {
            value[i].len = value[i].len - (sizeof("password=") - 1);
            if (!(server->password.len = value[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"password\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            value[i].data = &value[i].data[sizeof("password=") - 1];
            server->password.data = value[i].data;
        } else if (!ngx_strncmp(value[i].data, "application_name=", sizeof("application_name=") - 1)) {
            value[i].len = value[i].len - (sizeof("application_name=") - 1);
            if (!(server->application_name.len = value[i].len)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"application_name\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            value[i].data = &value[i].data[sizeof("application_name=") - 1];
            server->application_name.data = value[i].data;
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid parameter \"%V\" in \"postgres_server\"", &value[i]); return NGX_CONF_ERROR; }
    }
    upstream_srv_conf->peer.init_upstream = ngx_postgres_init_upstream;
    return NGX_CONF_OK;
}


static char *ngx_postgres_keepalive_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_conf_t *server_conf = conf;
    if (server_conf->max_save != 10 /* default */) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (cf->args->nelts == 2 && !ngx_strncmp(value[1].data, "off", sizeof("off") - 1)) { server_conf->max_save = 0; server_conf->prepare = 0; return NGX_CONF_OK; }
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (!ngx_strncmp(value[i].data, "save=", sizeof("save=") - 1)) {
            value[i].len = value[i].len - (sizeof("save=") - 1);
            value[i].data = &value[i].data[sizeof("save=") - 1];
            ngx_int_t n = ngx_atoi(value[i].data, value[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"save\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            server_conf->max_save = (ngx_uint_t) n;
        } else if (!ngx_strncmp(value[i].data, "mode=", sizeof("mode=") - 1)) {
            value[i].len = value[i].len - (sizeof("mode=") - 1);
            value[i].data = &value[i].data[sizeof("mode=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_mode_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == value[i].len && !ngx_strncasecmp(e[j].name.data, value[i].data, value[i].len)) { server_conf->single = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"mode\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
        } else if (!ngx_strncmp(value[i].data, "overflow=", sizeof("overflow=") - 1)) {
            value[i].len = value[i].len - (sizeof("overflow=") - 1);
            value[i].data = &value[i].data[sizeof("overflow=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_overflow_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == value[i].len && !ngx_strncasecmp(e[j].name.data, value[i].data, value[i].len)) { server_conf->reject = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"overflow\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
        } else if (!ngx_strncmp(value[i].data, "prepare=", sizeof("prepare=") - 1)) {
            value[i].len = value[i].len - (sizeof("prepare=") - 1);
            value[i].data = &value[i].data[sizeof("prepare=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_prepare_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == value[i].len && !ngx_strncasecmp(e[j].name.data, value[i].data, value[i].len)) { server_conf->prepare = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid \"prepare\" value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid parameter \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->upstream.upstream || location_conf->upstream_cv) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (!value[1].len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: empty upstream in \"%V\" directive", &cmd->name); return NGX_CONF_ERROR; }
    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_loc_conf->handler = ngx_postgres_handler;
    if (core_loc_conf->name.data[core_loc_conf->name.len - 1] == '/') core_loc_conf->auto_redirect = 1;
    if (ngx_http_script_variables_count(&value[1])) { /* complex value */
        if (!(location_conf->upstream_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        ngx_http_compile_complex_value_t ccv = {cf, &value[1], location_conf->upstream_cv, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    } else { /* simple value */
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.url = value[1];
        url.no_resolve = 1;
        if (!(location_conf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    }
}


static ngx_flag_t is_variable_character(u_char p) {
    return ((p >= '0' && p <= '9') || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || p == '_');
}


static ngx_uint_t type2oid(ngx_str_t *type) {
    ngx_conf_enum_t *e = ngx_postgres_oids;
    for (ngx_uint_t i = 0; e[i].name.len; i++) if (e[i].name.len - 3 == type->len && !ngx_strncasecmp(e[i].name.data, type->data, type->len)) return e[i].value;
    return 0;
}


static char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    ngx_str_t sql = value[cf->args->nelts - 1];
    if (!sql.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: empty query in \"%V\" directive", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_query_t *query;
    ngx_uint_t methods;
    ngx_postgres_location_conf_t *location_conf = conf;
    if (cf->args->nelts == 2) { /* default query */
        if (location_conf->query) return "is duplicate";
        if (!(location_conf->query = ngx_palloc(cf->pool, sizeof(ngx_postgres_query_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        methods = 0xFFFF;
        query = location_conf->query;
    } else { /* method-specific query */
        methods = 0;
        for (ngx_uint_t i = 1; i < cf->args->nelts - 1; i++) {
            ngx_conf_bitmask_t *b = ngx_postgres_http_methods;
            ngx_uint_t j;
            for (j = 0; b[j].name.len; j++) {
                if (b[j].name.len == value[i].len && !ngx_strncasecmp(b[j].name.data, value[i].data, value[i].len)) {
                    if (location_conf->methods_set & b[j].mask) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: method \"%V\" is duplicate in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
                    methods |= b[j].mask;
                    break;
                }
            }
            if (b[j].name.len == 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid method \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
        }
        if (!location_conf->methods && !(location_conf->methods = ngx_array_create(cf->pool, 4, sizeof(ngx_postgres_query_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        if (!(query = ngx_array_push(location_conf->methods))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        location_conf->methods_set |= methods;
    }
    query->methods = methods;
    if (!ngx_strncmp(sql.data, "file:", sizeof("file:") - 1)) {
        sql.data += sizeof("file:") - 1;
        sql.len -= sizeof("file:") - 1;
        if (ngx_conf_full_name(cf->cycle, &sql, 0) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "postgres: get full name \"%V\" failed", &sql); return NGX_CONF_ERROR; }
        ngx_fd_t fd = ngx_open_file(sql.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_open_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
        ngx_file_info_t fi;
        if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
            ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno, ngx_fd_info_n " \"%V\" failed", &sql);
            if (ngx_close_file(fd) == NGX_FILE_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
            return NGX_CONF_ERROR;
        }
        size_t len = ngx_file_size(&fi);
        u_char *data = ngx_pnalloc(cf->pool, len);
        if (!data) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s:%d", __FILE__, __LINE__);
            if (ngx_close_file(fd) == NGX_FILE_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
            return NGX_CONF_ERROR;
        }
        ssize_t n = ngx_read_fd(fd, data, len);
        if (n == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_read_fd_n " \"%V\" failed", &sql);
            if (ngx_close_file(fd) == NGX_FILE_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
            return NGX_CONF_ERROR;
        }
        if ((size_t) n != len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, ngx_read_fd_n " has read only %z of %O from \"%V\"", n, len, &sql);
            if (ngx_close_file(fd) == NGX_FILE_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
            return NGX_CONF_ERROR;
        }
        if (ngx_close_file(fd) == NGX_FILE_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_close_file_n " \"%V\" failed", &sql); return NGX_CONF_ERROR; }
        sql.data = data;
        sql.len = len;
    }
    if (!(query->sql.data = ngx_palloc(cf->pool, sql.len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    if (!(query->params = ngx_array_create(cf->pool, 4, sizeof(ngx_postgres_param_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    if (!(query->ids = ngx_array_create(cf->pool, 4, sizeof(ngx_uint_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    u_char *p = query->sql.data, *s = sql.data, *e = sql.data + sql.len;
    for (ngx_uint_t k = 0; s < e; *p++ = *s++) {
        if (*s == '%') *p++ = '%'; else if (*s == '$') {
            ngx_str_t name;
            for (name.data = ++s, name.len = 0; s < e && is_variable_character(*s); s++, name.len++);
            if (!name.len) { *p++ = '$'; continue; }
            ngx_str_t type = {0, NULL};
            if (s[0] == ':' && s[1] == ':') for (s += 2, type.data = s, type.len = 0; s < e && is_variable_character(*s); s++, type.len++);
            if (!type.len) { *p++ = '$'; p = ngx_copy(p, name.data, name.len); continue; }
            ngx_int_t index = ngx_http_get_variable_index(cf, &name);
            if (index == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid name \"%V\" in \"%V\" directive", &name, &cmd->name); return NGX_CONF_ERROR; }
            ngx_uint_t oid = type2oid(&type);
            if (!oid) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid oid \"%V\" in \"%V\" directive", &oid, &cmd->name);  return NGX_CONF_ERROR; }
            if (oid == IDOID) {
                ngx_uint_t *id = ngx_array_push(query->ids);
                if (!id) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
                *id = (ngx_uint_t) index;
                *p++ = '%';
                *p++ = 'V';
            } else {
                ngx_postgres_param_t *param = ngx_array_push(query->params);
                if (!param) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
                param->index = (ngx_uint_t) index;
                param->oid = oid;
                p += ngx_sprintf(p, "$%d", ++k) - p;
            }
            if (s >= e) break;
        }
    }
    query->sql.len = p - query->sql.data;
    query->listen =  !ngx_strncasecmp(query->sql.data, (u_char *)"LISTEN ", sizeof("LISTEN ") - 1);
//    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: sql = `%V`", &query->sql);
    return NGX_CONF_OK;
}


static char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    struct ngx_postgres_rewrite_enum_t *e = ngx_postgres_rewrite_handlers;
    ngx_str_t *value = cf->args->elts;
    ngx_str_t what = value[cf->args->nelts - 2];
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == what.len && !ngx_strncasecmp(e[i].name.data, what.data, what.len)) break;
    if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid condition \"%V\" in \"%V\" directive", &what, &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_location_conf_t *location_conf = conf;
    ngx_postgres_rewrite_conf_t *rewrite_conf;
    if (location_conf->rewrite_conf == NGX_CONF_UNSET_PTR) {
        if (!(location_conf->rewrite_conf = ngx_array_create(cf->pool, 2, sizeof(ngx_postgres_rewrite_conf_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    } else {
        rewrite_conf = location_conf->rewrite_conf->elts;
        for (ngx_uint_t j = 0; j < location_conf->rewrite_conf->nelts; j++) if (rewrite_conf[j].key == e[i].key) { rewrite_conf = &rewrite_conf[j]; goto found; }
    }
    if (!(rewrite_conf = ngx_array_push(location_conf->rewrite_conf))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_memzero(rewrite_conf, sizeof(ngx_postgres_rewrite_conf_t));
    rewrite_conf->key = e[i].key;
    rewrite_conf->handler = e[i].handler;
found:;
    ngx_uint_t methods;
    ngx_postgres_rewrite_t *rewrite;
    if (cf->args->nelts == 3) { /* default rewrite */
        if (rewrite_conf->rewrite) return "is duplicate";
        if (!(rewrite_conf->rewrite = ngx_palloc(cf->pool, sizeof(ngx_postgres_rewrite_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        methods = 0xFFFF;
        rewrite = rewrite_conf->rewrite;
    } else { /* method-specific rewrite */
        methods = 0;
        for (i = 1; i < cf->args->nelts - 2; i++) {
            ngx_conf_bitmask_t *b = ngx_postgres_http_methods;
            ngx_uint_t j;
            for (j = 0; b[j].name.len; j++) {
                if (b[j].name.len == value[i].len && !ngx_strncasecmp(b[j].name.data, value[i].data, value[i].len)) {
                    if (rewrite_conf->methods_set & b[j].mask) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: method \"%V\" for condition \"%V\" is duplicate in \"%V\" directive", &value[i], &what, &cmd->name); return NGX_CONF_ERROR; }
                    methods |= b[j].mask;
                    break;
                }
            }
            if (!b[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid method \"%V\" for condition \"%V\" in \"%V\" directive",  &value[i], &what, &cmd->name); return NGX_CONF_ERROR; }
        }
        if (!rewrite_conf->methods && !(rewrite_conf->methods = ngx_array_create(cf->pool, 4, sizeof(ngx_postgres_rewrite_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        if (!(rewrite = ngx_array_push(rewrite_conf->methods))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        rewrite_conf->methods_set |= methods;
    }
    ngx_str_t to = value[cf->args->nelts - 1];
    ngx_uint_t keep_body = 0;
    if (to.data[0] == '=') { keep_body = 1; to.len--; to.data++; }
    rewrite->methods = methods;
    rewrite->status = ngx_atoi(to.data, to.len);
    if (rewrite->status == NGX_ERROR || rewrite->status < NGX_HTTP_OK || rewrite->status > NGX_HTTP_INSUFFICIENT_STORAGE || (rewrite->status >= NGX_HTTP_SPECIAL_RESPONSE && rewrite->status < NGX_HTTP_BAD_REQUEST)) rewrite->location = to;
    if (keep_body) rewrite->status = -rewrite->status;
    return NGX_CONF_OK;
}


static char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->handler != NGX_CONF_UNSET_PTR) return "is duplicate";
    struct ngx_postgres_output_enum_t *e = ngx_postgres_output_handlers;
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == value[1].len && !ngx_strncasecmp(e[i].name.data, value[1].data, value[1].len)) { location_conf->handler = e[i].handler; break; }
    if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid output format \"%V\" in \"%V\" directive", &value[1], &cmd->name); return NGX_CONF_ERROR; }
    location_conf->binary = e[i].binary;
    return NGX_CONF_OK;
}


static char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *value = cf->args->elts;
    if (value[1].len < 2) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: empty variable name in \"%V\" directive", &cmd->name); return NGX_CONF_ERROR; }
    if (value[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid variable name \"%V\" in \"%V\" directive", &value[1], &cmd->name); }
    value[1].len--;
    value[1].data++;
    if (!value[3].len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: empty column in \"%V\" directive", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->variables == NGX_CONF_UNSET_PTR && !(location_conf->variables = ngx_array_create(cf->pool, 4, sizeof(ngx_postgres_variable_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_postgres_variable_t *variable = ngx_array_push(location_conf->variables);
    if (!variable) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    variable->index = location_conf->variables->nelts - 1;
    if (!(variable->variable = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    if (ngx_http_get_variable_index(cf, &value[1]) == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    if (!variable->variable->get_handler) {
        variable->variable->get_handler = ngx_postgres_variable_get_custom;
        variable->variable->data = (uintptr_t) variable;
    }
    if ((variable->value.row = ngx_atoi(value[2].data, value[2].len)) == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid row number \"%V\" in \"%V\" directive", &value[2], &cmd->name); return NGX_CONF_ERROR; }
    if ((variable->value.column = ngx_atoi(value[3].data, value[3].len)) == NGX_ERROR) { /* get column by name */
        if (!(variable->value.col_name = ngx_pnalloc(cf->pool, value[3].len + 1))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        (void) ngx_cpystrn(variable->value.col_name, value[3].data, value[3].len + 1);
    }
    if (cf->args->nelts == 4) { /* default value */
        variable->value.required = 0;
    } else { /* user-specified value */
        ngx_conf_enum_t *e = ngx_postgres_requirement_options;
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == value[4].len && !ngx_strncasecmp(e[i].name.data, value[4].data, value[4].len)) { variable->value.required = e[i].value; break; }
        if (!e[i].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "postgres: invalid requirement option \"%V\" in \"%V\" directive", &value[4], &cmd->name); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}


static ngx_command_t ngx_postgres_module_commands[] = {

    { ngx_string("postgres_server"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_postgres_server_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_postgres_keepalive_conf,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_postgres_pass_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_query"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
      ngx_postgres_query_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_rewrite"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_2MORE,
      ngx_postgres_rewrite_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_output"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_postgres_output_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE34,
      ngx_postgres_set_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("postgres_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_postgres_location_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("postgres_result_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_postgres_location_conf_t, upstream.read_timeout),
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_postgres_module_ctx = {
    ngx_postgres_add_variables,             /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_postgres_create_server_conf,        /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_postgres_create_location_conf,      /* create location configuration */
    ngx_postgres_merge_location_conf        /* merge location configuration */
};

ngx_module_t ngx_postgres_module = {
    NGX_MODULE_V1,
    &ngx_postgres_module_ctx,      /* module context */
    ngx_postgres_module_commands,  /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};