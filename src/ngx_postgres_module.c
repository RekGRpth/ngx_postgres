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
    { ngx_string("PGNODETREEOID"),  PGNODETREEOID },
    { ngx_string("PGNDISTINCTOID"),  PGNDISTINCTOID },
    { ngx_string("PGDEPENDENCIESOID"),  PGDEPENDENCIESOID },
    { ngx_string("PGMCVLISTOID"),  PGMCVLISTOID },
    { ngx_string("PGDDLCOMMANDOID"),  PGDDLCOMMANDOID },
    { ngx_string("POINTOID"),  POINTOID },
    { ngx_string("LSEGOID"),  LSEGOID },
    { ngx_string("PATHOID"),  PATHOID },
    { ngx_string("BOXOID"),  BOXOID },
    { ngx_string("POLYGONOID"),  POLYGONOID },
    { ngx_string("LINEOID"),  LINEOID },
    { ngx_string("FLOAT4OID"),  FLOAT4OID },
    { ngx_string("FLOAT8OID"),  FLOAT8OID },
    { ngx_string("UNKNOWNOID"),  UNKNOWNOID },
    { ngx_string("CIRCLEOID"),  CIRCLEOID },
    { ngx_string("CASHOID"),  CASHOID },
    { ngx_string("MACADDROID"),  MACADDROID },
    { ngx_string("INETOID"),  INETOID },
    { ngx_string("CIDROID"),  CIDROID },
    { ngx_string("MACADDR8OID"),  MACADDR8OID },
    { ngx_string("ACLITEMOID"),  ACLITEMOID },
    { ngx_string("BPCHAROID"),  BPCHAROID },
    { ngx_string("VARCHAROID"),  VARCHAROID },
    { ngx_string("DATEOID"),  DATEOID },
    { ngx_string("TIMEOID"),  TIMEOID },
    { ngx_string("TIMESTAMPOID"),  TIMESTAMPOID },
    { ngx_string("TIMESTAMPTZOID"),  TIMESTAMPTZOID },
    { ngx_string("INTERVALOID"),  INTERVALOID },
    { ngx_string("TIMETZOID"),  TIMETZOID },
    { ngx_string("BITOID"),  BITOID },
    { ngx_string("VARBITOID"),  VARBITOID },
    { ngx_string("NUMERICOID"),  NUMERICOID },
    { ngx_string("REFCURSOROID"),  REFCURSOROID },
    { ngx_string("REGPROCEDUREOID"),  REGPROCEDUREOID },
    { ngx_string("REGOPEROID"),  REGOPEROID },
    { ngx_string("REGOPERATOROID"),  REGOPERATOROID },
    { ngx_string("REGCLASSOID"),  REGCLASSOID },
    { ngx_string("REGTYPEOID"),  REGTYPEOID },
    { ngx_string("REGROLEOID"),  REGROLEOID },
    { ngx_string("REGNAMESPACEOID"),  REGNAMESPACEOID },
    { ngx_string("UUIDOID"),  UUIDOID },
    { ngx_string("LSNOID"),  LSNOID },
    { ngx_string("TSVECTOROID"),  TSVECTOROID },
    { ngx_string("GTSVECTOROID"),  GTSVECTOROID },
    { ngx_string("TSQUERYOID"),  TSQUERYOID },
    { ngx_string("REGCONFIGOID"),  REGCONFIGOID },
    { ngx_string("REGDICTIONARYOID"),  REGDICTIONARYOID },
    { ngx_string("JSONBOID"),  JSONBOID },
    { ngx_string("JSONPATHOID"),  JSONPATHOID },
    { ngx_string("TXID_SNAPSHOTOID"),  TXID_SNAPSHOTOID },
    { ngx_string("INT4RANGEOID"),  INT4RANGEOID },
    { ngx_string("NUMRANGEOID"),  NUMRANGEOID },
    { ngx_string("TSRANGEOID"),  TSRANGEOID },
    { ngx_string("TSTZRANGEOID"),  TSTZRANGEOID },
    { ngx_string("DATERANGEOID"),  DATERANGEOID },
    { ngx_string("INT8RANGEOID"),  INT8RANGEOID },
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
    { ngx_string("TABLE_AM_HANDLEROID"),  TABLE_AM_HANDLEROID },
    { ngx_string("ANYRANGEOID"),  ANYRANGEOID },
    { ngx_string("BOOLARRAYOID"),  BOOLARRAYOID },
    { ngx_string("BYTEAARRAYOID"),  BYTEAARRAYOID },
    { ngx_string("CHARARRAYOID"),  CHARARRAYOID },
    { ngx_string("NAMEARRAYOID"),  NAMEARRAYOID },
    { ngx_string("INT8ARRAYOID"),  INT8ARRAYOID },
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
    { ngx_string("JSONARRAYOID"),  JSONARRAYOID },
    { ngx_string("XMLARRAYOID"),  XMLARRAYOID },
    { ngx_string("POINTARRAYOID"),  POINTARRAYOID },
    { ngx_string("LSEGARRAYOID"),  LSEGARRAYOID },
    { ngx_string("PATHARRAYOID"),  PATHARRAYOID },
    { ngx_string("BOXARRAYOID"),  BOXARRAYOID },
    { ngx_string("POLYGONARRAYOID"),  POLYGONARRAYOID },
    { ngx_string("LINEARRAYOID"),  LINEARRAYOID },
    { ngx_string("FLOAT4ARRAYOID"),  FLOAT4ARRAYOID },
    { ngx_string("FLOAT8ARRAYOID"),  FLOAT8ARRAYOID },
    { ngx_string("CIRCLEARRAYOID"),  CIRCLEARRAYOID },
    { ngx_string("MONEYARRAYOID"),  MONEYARRAYOID },
    { ngx_string("MACADDRARRAYOID"),  MACADDRARRAYOID },
    { ngx_string("INETARRAYOID"),  INETARRAYOID },
    { ngx_string("CIDRARRAYOID"),  CIDRARRAYOID },
    { ngx_string("MACADDR8ARRAYOID"),  MACADDR8ARRAYOID },
    { ngx_string("ACLITEMARRAYOID"),  ACLITEMARRAYOID },
    { ngx_string("BPCHARARRAYOID"),  BPCHARARRAYOID },
    { ngx_string("VARCHARARRAYOID"),  VARCHARARRAYOID },
    { ngx_string("DATEARRAYOID"),  DATEARRAYOID },
    { ngx_string("TIMEARRAYOID"),  TIMEARRAYOID },
    { ngx_string("TIMESTAMPARRAYOID"),  TIMESTAMPARRAYOID },
    { ngx_string("TIMESTAMPTZARRAYOID"),  TIMESTAMPTZARRAYOID },
    { ngx_string("INTERVALARRAYOID"),  INTERVALARRAYOID },
    { ngx_string("TIMETZARRAYOID"),  TIMETZARRAYOID },
    { ngx_string("BITARRAYOID"),  BITARRAYOID },
    { ngx_string("VARBITARRAYOID"),  VARBITARRAYOID },
    { ngx_string("NUMERICARRAYOID"),  NUMERICARRAYOID },
    { ngx_string("REFCURSORARRAYOID"),  REFCURSORARRAYOID },
    { ngx_string("REGPROCEDUREARRAYOID"),  REGPROCEDUREARRAYOID },
    { ngx_string("REGOPERARRAYOID"),  REGOPERARRAYOID },
    { ngx_string("REGOPERATORARRAYOID"),  REGOPERATORARRAYOID },
    { ngx_string("REGCLASSARRAYOID"),  REGCLASSARRAYOID },
    { ngx_string("REGTYPEARRAYOID"),  REGTYPEARRAYOID },
    { ngx_string("REGROLEARRAYOID"),  REGROLEARRAYOID },
    { ngx_string("REGNAMESPACEARRAYOID"),  REGNAMESPACEARRAYOID },
    { ngx_string("UUIDARRAYOID"),  UUIDARRAYOID },
    { ngx_string("PG_LSNARRAYOID"),  PG_LSNARRAYOID },
    { ngx_string("TSVECTORARRAYOID"),  TSVECTORARRAYOID },
    { ngx_string("GTSVECTORARRAYOID"),  GTSVECTORARRAYOID },
    { ngx_string("TSQUERYARRAYOID"),  TSQUERYARRAYOID },
    { ngx_string("REGCONFIGARRAYOID"),  REGCONFIGARRAYOID },
    { ngx_string("REGDICTIONARYARRAYOID"),  REGDICTIONARYARRAYOID },
    { ngx_string("JSONBARRAYOID"),  JSONBARRAYOID },
    { ngx_string("JSONPATHARRAYOID"),  JSONPATHARRAYOID },
    { ngx_string("TXID_SNAPSHOTARRAYOID"),  TXID_SNAPSHOTARRAYOID },
    { ngx_string("INT4RANGEARRAYOID"),  INT4RANGEARRAYOID },
    { ngx_string("NUMRANGEARRAYOID"),  NUMRANGEARRAYOID },
    { ngx_string("TSRANGEARRAYOID"),  TSRANGEARRAYOID },
    { ngx_string("TSTZRANGEARRAYOID"),  TSTZRANGEARRAYOID },
    { ngx_string("DATERANGEARRAYOID"),  DATERANGEARRAYOID },
    { ngx_string("INT8RANGEARRAYOID"),  INT8RANGEARRAYOID },
    { ngx_string("CSTRINGARRAYOID"),  CSTRINGARRAYOID },
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
    { ngx_string("no"), 0 },
    { ngx_string("false"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("yes"), 1 },
    { ngx_string("true"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_output_options[] = {
    { ngx_string("off"), 0 },
    { ngx_string("no"), 0 },
    { ngx_string("false"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("yes"), 1 },
    { ngx_string("true"), 1 },
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
    { ngx_string("csv") ,         0, ngx_postgres_output_csv },
    { ngx_string("value"),        0, ngx_postgres_output_value },
    { ngx_string("binary"),       1, ngx_postgres_output_value },
    { ngx_string("json"),         0, ngx_postgres_output_json },
    { ngx_null_string, 0, NULL }
};


static ngx_int_t ngx_postgres_add_variables(ngx_conf_t *cf) {
    for (ngx_http_variable_t *v = ngx_postgres_module_variables; v->name.len; v++) {
        ngx_http_variable_t *variable = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!variable) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_http_add_variable"); return NGX_ERROR; }
        variable->get_handler = v->get_handler;
        variable->data = v->data;
    }
    return NGX_OK;
}


static void ngx_postgres_server_conf_cleanup(void *data) {
//    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "%s", __func__);
    ngx_postgres_server_conf_t *server_conf = data;
    if (!server_conf->busy.prev) return; /* ngx_queue_empty is broken when used on unitialized queue */
    server_conf->max_save = 0; /* just to be on the safe-side */
    while (!ngx_queue_empty(&server_conf->busy)) {
        ngx_queue_t *queue = ngx_queue_head(&server_conf->busy);
        ngx_queue_remove(queue);
        ngx_postgres_save_t *save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_postgres_free_connection(save->connection, &save->common, NULL, 0);
    }
}


static void *ngx_postgres_create_server_conf(ngx_conf_t *cf) {
    ngx_postgres_server_conf_t *server_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_server_conf_t));
    if (!server_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    /* enable keepalive (single) by default */
    server_conf->max_save = 10;
    server_conf->single = 1;
    server_conf->prepare = 1;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pool_cleanup_add"); return NULL; }
    cln->handler = ngx_postgres_server_conf_cleanup;
    cln->data = server_conf;
    return server_conf;
}


static void *ngx_postgres_create_location_conf(ngx_conf_t *cf) {
    ngx_postgres_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_location_conf_t));
    if (!location_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    location_conf->upstream.upstream_conf.connect_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->upstream.upstream_conf.read_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->rewrite_conf = NGX_CONF_UNSET_PTR;
    location_conf->output.header = 1;
    location_conf->output.string_quote_only = 1;
    location_conf->variables = NGX_CONF_UNSET_PTR;
    /* the hardcoded values */
    location_conf->upstream.upstream_conf.cyclic_temp_file = 0;
    location_conf->upstream.upstream_conf.buffering = 1;
    location_conf->upstream.upstream_conf.ignore_client_abort = 1;
    location_conf->upstream.upstream_conf.send_lowat = 0;
    location_conf->upstream.upstream_conf.bufs.num = 0;
    location_conf->upstream.upstream_conf.busy_buffers_size = 0;
    location_conf->upstream.upstream_conf.max_temp_file_size = 0;
    location_conf->upstream.upstream_conf.temp_file_write_size = 0;
    location_conf->upstream.upstream_conf.intercept_errors = 1;
    location_conf->upstream.upstream_conf.intercept_404 = 1;
    location_conf->upstream.upstream_conf.pass_request_headers = 0;
    location_conf->upstream.upstream_conf.pass_request_body = 0;
    return location_conf;
}


static char *ngx_postgres_merge_location_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_postgres_location_conf_t *prev = parent;
    ngx_postgres_location_conf_t *conf = child;
    ngx_conf_merge_msec_value(conf->upstream.upstream_conf.connect_timeout, prev->upstream.upstream_conf.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.upstream_conf.read_timeout, prev->upstream.upstream_conf.read_timeout, 60000);
    if (!conf->upstream.upstream_conf.upstream && !conf->upstream.complex_value) {
        conf->upstream.upstream_conf = prev->upstream.upstream_conf;
        conf->upstream.complex_value = prev->upstream.complex_value;
    }
    if (!conf->query && !conf->methods) {
        conf->methods_set = prev->methods_set;
        conf->methods = prev->methods;
        conf->query = prev->query;
    }
    ngx_conf_merge_ptr_value(conf->rewrite_conf, prev->rewrite_conf, NULL);
    if (!conf->output.handler && prev->output.handler) conf->output = prev->output;
    ngx_conf_merge_ptr_value(conf->variables, prev->variables, NULL);
    return NGX_CONF_OK;
}


static ngx_int_t ngx_postgres_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    upstream_srv_conf->peer.init = ngx_postgres_peer_init;
    ngx_postgres_server_conf_t *server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    if (!upstream_srv_conf->servers || !upstream_srv_conf->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &upstream_srv_conf->host, upstream_srv_conf->file_name, upstream_srv_conf->line); return NGX_ERROR; }
    ngx_postgres_server_t *server = upstream_srv_conf->servers->elts;
    ngx_uint_t n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) n += server[i].naddrs;
    ngx_postgres_peers_t *peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_peers_t) + sizeof(ngx_postgres_peer_t) * (n - 1));
    if (!peers) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    peers->single = (n == 1);
    peers->max_peer = n;
    n = 0;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < server[i].naddrs; j++) {
            ngx_postgres_peer_t *peer = &peers->peer[n];
            peer->sockaddr = server[i].addrs[j].sockaddr;
            peer->socklen = server[i].addrs[j].socklen;
            peer->name = &server[i].addrs[j].name;
            if (!(peer->host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(peer->host.len = ngx_sock_ntop(peer->sockaddr, peer->socklen, peer->host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_sock_ntop"); return NGX_ERROR; }
            size_t len = server[i].family == AF_UNIX ? sizeof("host=%s") - 1 - 1 + peer->host.len - 5 : sizeof("hostaddr=%V") - 1 - 1 + peer->host.len;
            len += sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1;
            if (server[i].dbname.len) len += sizeof(" dbname=%V") - 1 - 1 + server[i].dbname.len;
            if (server[i].user.len) len += sizeof(" user=%V") - 1 - 1 + server[i].user.len;
            if (server[i].password.len) len += sizeof(" password=%V") - 1 - 1 + server[i].password.len;
            if (server[i].application_name.len) len += sizeof(" application_name=%V") - 1 - 1 + server[i].application_name.len;
            if (!(peer->connstring = ngx_pnalloc(cf->pool, len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
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
    if (!server_conf->max_save) return NGX_OK;
    ngx_queue_init(&server_conf->busy);
    ngx_queue_init(&server_conf->free);
    ngx_postgres_save_t *save;
    for (ngx_uint_t i = 0; i < server_conf->max_save; i++) {
        if (!(save = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_save_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        ngx_queue_insert_head(&server_conf->free, &save->queue);
        save->common.server_conf = server_conf;
    }
    return NGX_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { /* Based on: ngx_http_upstream.c/ngx_http_upstream_server Copyright (C) Igor Sysoev */
    ngx_http_upstream_srv_conf_t *upstream_srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (!upstream_srv_conf->servers && !(upstream_srv_conf->servers = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_server_t)))) return "!ngx_array_create";
    ngx_postgres_server_t *server = ngx_array_push(upstream_srv_conf->servers);
    if (!server) return "!ngx_array_push";
    ngx_memzero(server, sizeof(ngx_postgres_server_t));
    /* parse the first name:port argument */
    ngx_url_t u;
    ngx_memzero(&u, sizeof(ngx_url_t));
    ngx_str_t *elts = cf->args->elts;
    u.url = elts[1];
    u.default_port = 5432; /* PostgreSQL default */
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) { if (u.err) return u.err; return "ngx_parse_url != NGX_OK"; }
    server->addrs = u.addrs;
    server->naddrs = u.naddrs;
    server->port = u.family == AF_UNIX ? u.default_port : u.port;
    server->family = u.family;
    /* parse various options */
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("port=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"port=", sizeof("port=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("port=") - 1);
            elts[i].data = &elts[i].data[sizeof("port=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server->port = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("dbname=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"dbname=", sizeof("dbname=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("dbname=") - 1);
            if (!(server->dbname.len = elts[i].len)) return "!server->dbname.len";
            elts[i].data = &elts[i].data[sizeof("dbname=") - 1];
            server->dbname.data = elts[i].data;
        } else if (elts[i].len > sizeof("user=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"user=", sizeof("user=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("user=") - 1);
            if (!(server->user.len = elts[i].len)) return "!server->user.len";
            elts[i].data = &elts[i].data[sizeof("user=") - 1];
            server->user.data = elts[i].data;
        } else if (elts[i].len > sizeof("password=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"password=", sizeof("password=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("password=") - 1);
            if (!(server->password.len = elts[i].len)) return "!server->password.len";
            elts[i].data = &elts[i].data[sizeof("password=") - 1];
            server->password.data = elts[i].data;
        } else if (elts[i].len > sizeof("application_name=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"application_name=", sizeof("application_name=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("application_name=") - 1);
            if (!(server->application_name.len = elts[i].len)) return "!server->application_name.len";
            elts[i].data = &elts[i].data[sizeof("application_name=") - 1];
            server->application_name.data = elts[i].data;
        } else return "invalid parameter";
    }
    upstream_srv_conf->peer.init_upstream = ngx_postgres_init_upstream;
    return NGX_CONF_OK;
}


static char *ngx_postgres_keepalive_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_conf_t *server_conf = conf;
    if (server_conf->max_save != 10 /* default */) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (cf->args->nelts == 2 && ((elts[1].len == sizeof("off") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"off", sizeof("off") - 1)) || (elts[1].len == sizeof("no") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"no", sizeof("no") - 1)) || (elts[1].len == sizeof("false") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"false", sizeof("false") - 1)))) { server_conf->max_save = 0; server_conf->prepare = 0; return NGX_CONF_OK; }
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("requests=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"requests=", sizeof("requests=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("requests=") - 1);
            elts[i].data = &elts[i].data[sizeof("requests=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server_conf->max_requests = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 0);
            if (n == NGX_ERROR) return "ngx_parse_time == NGX_ERROR";
            server_conf->timeout = (ngx_msec_t) n;
        } else if (elts[i].len > sizeof("save=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"save=", sizeof("save=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("save=") - 1);
            elts[i].data = &elts[i].data[sizeof("save=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server_conf->max_save = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("mode=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"mode=", sizeof("mode=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("mode=") - 1);
            elts[i].data = &elts[i].data[sizeof("mode=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_mode_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->single = e[j].value; break; }
            if (!e[j].name.len) return "invalid mode";
        } else if (elts[i].len > sizeof("overflow=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("overflow=") - 1);
            elts[i].data = &elts[i].data[sizeof("overflow=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_overflow_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->reject = e[j].value; break; }
            if (!e[j].name.len) return "invalid overflow";
        } else if (elts[i].len > sizeof("prepare=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"prepare=", sizeof("prepare=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("prepare=") - 1);
            elts[i].data = &elts[i].data[sizeof("prepare=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_prepare_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->prepare = e[j].value; break; }
            if (!e[j].name.len) return "invalid prepare";
        } else return "invalid parameter";
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->upstream.upstream_conf.upstream || location_conf->upstream.complex_value) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (!elts[1].len) return "empty upstream";
    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_loc_conf->handler = ngx_postgres_handler;
    if (core_loc_conf->name.data[core_loc_conf->name.len - 1] == '/') core_loc_conf->auto_redirect = 1;
    if (ngx_http_script_variables_count(&elts[1])) { /* complex value */
        if (!(location_conf->upstream.complex_value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t)))) return "!ngx_palloc";
        ngx_http_compile_complex_value_t ccv = {cf, &elts[1], location_conf->upstream.complex_value, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        return NGX_CONF_OK;
    } else { /* simple value */
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.url = elts[1];
        url.no_resolve = 1;
        if (!(location_conf->upstream.upstream_conf.upstream = ngx_http_upstream_add(cf, &url, 0))) return "!ngx_http_upstream_add";
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
    ngx_str_t *elts = cf->args->elts;
    ngx_str_t sql = elts[cf->args->nelts - 1];
    if (!sql.len) return "empty query";
    ngx_postgres_query_t *query;
    ngx_uint_t methods;
    ngx_postgres_location_conf_t *location_conf = conf;
    if (cf->args->nelts == 2) { /* default query */
        if (location_conf->query) return "is duplicate";
        if (!(location_conf->query = ngx_palloc(cf->pool, sizeof(ngx_postgres_query_t)))) return "!ngx_palloc";
        methods = 0xFFFF;
        query = location_conf->query;
    } else { /* method-specific query */
        methods = 0;
        for (ngx_uint_t i = 1; i < cf->args->nelts - 1; i++) {
            ngx_conf_bitmask_t *b = ngx_postgres_http_methods;
            ngx_uint_t j;
            for (j = 0; b[j].name.len; j++) {
                if (b[j].name.len == elts[i].len && !ngx_strncasecmp(b[j].name.data, elts[i].data, elts[i].len)) {
                    if (location_conf->methods_set & b[j].mask) return "method is duplicate";
                    methods |= b[j].mask;
                    break;
                }
            }
            if (!b[j].name.len) return "invalid method";
        }
        if (!location_conf->methods && !(location_conf->methods = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_query_t)))) return "!ngx_array_create";
        if (!(query = ngx_array_push(location_conf->methods))) return "!ngx_array_push";
        location_conf->methods_set |= methods;
    }
    query->methods = methods;
    if (sql.len > sizeof("file:") - 1 && !ngx_strncasecmp(sql.data, (u_char *)"file:", sizeof("file:") - 1)) {
        sql.data += sizeof("file:") - 1;
        sql.len -= sizeof("file:") - 1;
        if (ngx_conf_full_name(cf->cycle, &sql, 0) != NGX_OK) return "ngx_conf_full_name != NGX_OK";
        ngx_fd_t fd = ngx_open_file(sql.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) return "ngx_open_file == NGX_INVALID_FILE";
        ngx_file_info_t fi;
        if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_fd_info == NGX_FILE_ERROR"; }
        size_t len = ngx_file_size(&fi);
        u_char *data = ngx_pnalloc(cf->pool, len);
        if (!data) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "!ngx_pnalloc"; }
        ssize_t n = ngx_read_fd(fd, data, len);
        if (n == -1) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_read_fd == -1"; }
        if ((size_t) n != len) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_read_fd != len"; }
        if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR";
        sql.data = data;
        sql.len = len;
    }
    if (!(query->sql.data = ngx_palloc(cf->pool, sql.len))) return "!ngx_palloc";
    if (!(query->params = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_param_t)))) return "!ngx_array_create";
    if (!(query->ids = ngx_array_create(cf->pool, 1, sizeof(ngx_uint_t)))) return "!ngx_array_create";
    u_char *p = query->sql.data, *s = sql.data, *e = sql.data + sql.len;
    query->percent = 0;
    for (ngx_uint_t k = 0; s < e; *p++ = *s++) {
        if (*s == '%') {
            *p++ = '%';
            query->percent++;
        } else if (*s == '$') {
            ngx_str_t name;
            for (name.data = ++s, name.len = 0; s < e && is_variable_character(*s); s++, name.len++);
            if (!name.len) { *p++ = '$'; continue; }
            ngx_str_t type = {0, NULL};
            if (s[0] == ':' && s[1] == ':') for (s += 2, type.data = s, type.len = 0; s < e && is_variable_character(*s); s++, type.len++);
            if (!type.len) { *p++ = '$'; p = ngx_copy(p, name.data, name.len); continue; }
            ngx_int_t index = ngx_http_get_variable_index(cf, &name);
            if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            ngx_uint_t oid = type2oid(&type);
            if (!oid) return "!type2oid";
            if (oid == IDOID) {
                ngx_uint_t *id = ngx_array_push(query->ids);
                if (!id) return "!ngx_array_push";
                *id = (ngx_uint_t) index;
                *p++ = '%';
                *p++ = 'V';
            } else {
                ngx_postgres_param_t *param = ngx_array_push(query->params);
                if (!param) return "!ngx_array_push";
                param->index = (ngx_uint_t) index;
                param->oid = oid;
                p += ngx_sprintf(p, "$%d", ++k) - p;
            }
            if (s >= e) break;
        }
    }
    query->sql.len = p - query->sql.data;
    query->listen = query->sql.len > sizeof("LISTEN ") - 1 && !ngx_strncasecmp(query->sql.data, (u_char *)"LISTEN ", sizeof("LISTEN ") - 1);
//    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "sql = `%V`", &query->sql);
    return NGX_CONF_OK;
}


static char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    struct ngx_postgres_rewrite_enum_t *e = ngx_postgres_rewrite_handlers;
    ngx_str_t *elts = cf->args->elts;
    ngx_str_t what = elts[cf->args->nelts - 2];
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == what.len && !ngx_strncasecmp(e[i].name.data, what.data, what.len)) break;
    if (!e[i].name.len) return "invalid condition";
    ngx_postgres_location_conf_t *location_conf = conf;
    ngx_postgres_rewrite_conf_t *rewrite_conf;
    if (location_conf->rewrite_conf == NGX_CONF_UNSET_PTR) {
        if (!(location_conf->rewrite_conf = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_rewrite_conf_t)))) return "!ngx_array_create";
    } else {
        rewrite_conf = location_conf->rewrite_conf->elts;
        for (ngx_uint_t j = 0; j < location_conf->rewrite_conf->nelts; j++) if (rewrite_conf[j].key == e[i].key) { rewrite_conf = &rewrite_conf[j]; goto found; }
    }
    if (!(rewrite_conf = ngx_array_push(location_conf->rewrite_conf))) return "!ngx_array_push";
    ngx_memzero(rewrite_conf, sizeof(ngx_postgres_rewrite_conf_t));
    rewrite_conf->key = e[i].key;
    rewrite_conf->handler = e[i].handler;
found:;
    ngx_uint_t methods;
    ngx_postgres_rewrite_t *rewrite;
    if (cf->args->nelts == 3) { /* default rewrite */
        if (rewrite_conf->rewrite) return "is duplicate";
        if (!(rewrite_conf->rewrite = ngx_palloc(cf->pool, sizeof(ngx_postgres_rewrite_t)))) return "!ngx_palloc";
        methods = 0xFFFF;
        rewrite = rewrite_conf->rewrite;
    } else { /* method-specific rewrite */
        methods = 0;
        for (i = 1; i < cf->args->nelts - 2; i++) {
            ngx_conf_bitmask_t *b = ngx_postgres_http_methods;
            ngx_uint_t j;
            for (j = 0; b[j].name.len; j++) {
                if (b[j].name.len == elts[i].len && !ngx_strncasecmp(b[j].name.data, elts[i].data, elts[i].len)) {
                    if (rewrite_conf->methods_set & b[j].mask) return "method is duplicate";
                    methods |= b[j].mask;
                    break;
                }
            }
            if (!b[j].name.len) return "invalid method";
        }
        if (!rewrite_conf->methods && !(rewrite_conf->methods = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_rewrite_t)))) return "!ngx_array_create";
        if (!(rewrite = ngx_array_push(rewrite_conf->methods))) return "!ngx_array_push";
        rewrite_conf->methods_set |= methods;
    }
    ngx_str_t to = elts[cf->args->nelts - 1];
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
    if (location_conf->output.handler) return "is duplicate";
    struct ngx_postgres_output_enum_t *e = ngx_postgres_output_handlers;
    ngx_str_t *elts = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[1].len && !ngx_strncasecmp(e[i].name.data, elts[1].data, elts[1].len)) { location_conf->output.handler = e[i].handler; break; }
    if (!e[i].name.len) return "invalid output format";
    location_conf->output.binary = e[i].binary;
    if (cf->args->nelts > 2 && location_conf->output.handler != ngx_postgres_output_text && location_conf->output.handler != ngx_postgres_output_csv) return "invalid extra parameters for output format";
    if (location_conf->output.handler == ngx_postgres_output_text) {
        location_conf->output.delimiter = '\t';
        ngx_str_set(&location_conf->output.null, "\\N");
    } else if (location_conf->output.handler == ngx_postgres_output_csv) {
        location_conf->output.delimiter = ',';
        ngx_str_set(&location_conf->output.null, "");
        location_conf->output.quote = '"';
        location_conf->output.escape = '"';
    }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("delimiter=") - 1);
            if (!elts[i].len || elts[i].len > 1) return "invalid delimiter";
            elts[i].data = &elts[i].data[sizeof("delimiter=") - 1];
            location_conf->output.delimiter = *elts[i].data;
        } else if (elts[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("null=") - 1);
            if (!(location_conf->output.null.len = elts[i].len)) return "invalid null";
            elts[i].data = &elts[i].data[sizeof("null=") - 1];
            location_conf->output.null.data = elts[i].data;
        } else if (elts[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("header=") - 1);
            elts[i].data = &elts[i].data[sizeof("header=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.header = e[j].value; break; }
            if (!e[j].name.len) return "invalid header";
        } else if (elts[i].len > sizeof("string_quote_only=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"string_quote_only=", sizeof("string_quote_only=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("string_quote_only=") - 1);
            elts[i].data = &elts[i].data[sizeof("string_quote_only=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.string_quote_only = e[j].value; break; }
            if (!e[j].name.len) return "invalid string_quote_only";
        } else if (elts[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("quote=") - 1);
            if (!elts[i].len) { location_conf->output.quote = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid quote";
            elts[i].data = &elts[i].data[sizeof("quote=") - 1];
            location_conf->output.quote = *elts[i].data;
        } else if (elts[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("escape=") - 1);
            if (!elts[i].len) { location_conf->output.escape = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid escape";
            elts[i].data = &elts[i].data[sizeof("escape=") - 1];
            location_conf->output.escape = *elts[i].data;
        } else return "invalid parameter";
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len < 2) return "empty variable name";
    if (elts[1].data[0] != '$') return "invalid variable name";
    elts[1].len--;
    elts[1].data++;
    if (!elts[3].len) return "empty column";
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->variables == NGX_CONF_UNSET_PTR && !(location_conf->variables = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_variable_t)))) return "!ngx_array_create";
    ngx_postgres_variable_t *variable = ngx_array_push(location_conf->variables);
    if (!variable) return "!ngx_array_push";
    variable->index = location_conf->variables->nelts - 1;
    if (!(variable->variable = ngx_http_add_variable(cf, &elts[1], NGX_HTTP_VAR_CHANGEABLE))) return "!ngx_http_add_variable";
    if (ngx_http_get_variable_index(cf, &elts[1]) == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
    if (!variable->variable->get_handler) {
        variable->variable->get_handler = ngx_postgres_variable_get_custom;
        variable->variable->data = (uintptr_t) variable;
    }
    if ((variable->value.row = ngx_atoi(elts[2].data, elts[2].len)) == NGX_ERROR) return "invalid row number";
    if ((variable->value.column = ngx_atoi(elts[3].data, elts[3].len)) == NGX_ERROR) { /* get column by name */
        if (!(variable->value.col_name = ngx_pnalloc(cf->pool, elts[3].len + 1))) return "!ngx_pnalloc";
        (void) ngx_cpystrn(variable->value.col_name, elts[3].data, elts[3].len + 1);
    }
    if (cf->args->nelts == 4) { /* default value */
        variable->value.required = 0;
    } else { /* user-specified value */
        ngx_conf_enum_t *e = ngx_postgres_requirement_options;
        ngx_uint_t i;
        for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[4].len && !ngx_strncasecmp(e[i].name.data, elts[4].data, elts[4].len)) { variable->value.required = e[i].value; break; }
        if (!e[i].name.len) return "invalid requirement option";
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
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
      offsetof(ngx_postgres_upstream_t, upstream_conf.connect_timeout),
      NULL },

    { ngx_string("postgres_result_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_postgres_upstream_t, upstream_conf.read_timeout),
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
