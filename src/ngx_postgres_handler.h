#ifndef _NGX_POSTGRES_HANDLER_H_
#define _NGX_POSTGRES_HANDLER_H_

#include <ngx_http.h>

ngx_int_t ngx_postgres_handler(ngx_http_request_t *);
void ngx_postgres_finalize_upstream(ngx_http_request_t *, ngx_http_upstream_t *, ngx_int_t);
void ngx_postgres_next_upstream(ngx_http_request_t *, ngx_http_upstream_t *, ngx_int_t);

#endif /* _NGX_POSTGRES_HANDLER_H_ */
