/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * Copyright (C) 2008, Maxim Dounin
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NGX_POSTGRES_KEEPALIVE_H_
#define _NGX_POSTGRES_KEEPALIVE_H_

#include <ngx_http.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_upstream.h"


ngx_int_t   ngx_postgres_keepalive_init(ngx_pool_t *, ngx_postgres_srv_conf_t *);
ngx_int_t   ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *, ngx_postgres_upstream_peer_data_t *);
ngx_int_t   ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *, ngx_postgres_upstream_peer_data_t *);
void        ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *, ngx_postgres_upstream_peer_data_t *, ngx_uint_t);
void        ngx_postgres_keepalive_cleanup(void *);

#endif /* _NGX_POSTGRES_KEEPALIVE_H_ */
