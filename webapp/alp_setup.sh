#!/bin/bash

# nginxのログ形式変更
nginx_config_content=$(cat <<EOL
user  www-data;
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format ltsv "time:\$time_local"
                    "\thost:\$remote_addr"
                    "\tforwardedfor:\$http_x_forwarded_for"
                    "\treq:\$request"
                    "\tstatus:\$status"
                    "\tmethod:\$request_method"
                    "\turi:\$request_uri"
                    "\tsize:\$body_bytes_sent"
                    "\treferer:\$http_referer"
                    "\tua:\$http_user_agent"
                    "\treqtime:\$request_time"
                    "\tcache:\$upstream_http_x_cache"
                    "\truntime:\$upstream_http_x_runtime"
                    "\tapptime:\$upstream_response_time"
                    "\tvhost:\$host";
    access_log /var/log/nginx/access.log ltsv;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*.conf;
}
EOL
)
file_path="/etc/nginx/nginx.conf"
echo "$nginx_config_content" > "$file_path"
chmod 644 /var/log/nginx/access.log

# nginxの再起動
sleep 3
systemctl restart nginx

# alpインストール
wget https://github.com/tkuchiki/alp/releases/download/v1.0.21/alp_linux_arm64.tar.gz
tar -xvf alp_linux_arm64.tar.gz
install alp /usr/local/bin/alp