#ifndef _NGX_POSTGRES_OUTPUT_H_
#define _NGX_POSTGRES_OUTPUT_H_

#include <ngx_http.h>

char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_postgres_output_chain(ngx_http_request_t *);

#endif /* _NGX_POSTGRES_OUTPUT_H_ */
