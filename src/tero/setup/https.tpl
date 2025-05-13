# whitelabel for %(subdomain)s

server {
        listen          80;
        server_name     %(top_domain)s %(domain)s;

        access_log %(LOCALSTATEDIR)s/log/nginx/%(domain)s-access.log main;
        error_log  %(LOCALSTATEDIR)s/log/nginx/%(domain)s-error.log;

        # Only requests to our Host are allowed
        if ($http_host !~* ^(.*\.)?%(top_domain)s$ ) {
            return 444;
        }

        # Block download user agents
        if ($http_user_agent ~* YoudaoBot|Sogou|YandexBot|linkdexbot|panscient) {
            return 403;
        }

        root %(htdocs_dir)s;

        location / {
            return 301 https://$host$request_uri;
        }
}


server {
        listen       443 ssl;
        server_name  %(top_domain)s;

        access_log %(LOCALSTATEDIR)s/log/nginx/%(domain)s-access.log main;
        error_log  %(LOCALSTATEDIR)s/log/nginx/%(domain)s-error.log;

        ssl_certificate      %(ssl_fullchain_path)s;
        ssl_certificate_key  %(ssl_key_path)s;
        ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
        ssl_protocols TLSv1.3 TLSv1.2;
        ssl_dhparam /etc/pki/tls/certs/dhparam.pem;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout  5m;

        client_max_body_size 4G;
        keepalive_timeout 5;

        # Only requests to our Host are allowed
        if ( $http_host !~* ^%(top_domain)s$ ) {
            return 444;
        }

        # Block download user agents
        if ($http_user_agent ~* YoudaoBot|Sogou|YandexBot|linkdexbot|panscient) {
            return 403;
        }

        # path for static files
        root %(htdocs_dir)s;

        location / {
            return 302 https://%(domain)s$request_uri;
        }
}


server {
        listen       443 ssl;
        server_name  %(domain)s;

        access_log %(LOCALSTATEDIR)s/log/nginx/%(domain)s-access.log main;
        error_log  %(LOCALSTATEDIR)s/log/nginx/%(domain)s-error.log;

        ssl_certificate      %(ssl_fullchain_path)s;
        ssl_certificate_key  %(ssl_key_path)s;
        ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
        ssl_protocols TLSv1.3 TLSv1.2;
        ssl_dhparam /etc/pki/tls/certs/dhparam.pem;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout  5m;

        client_max_body_size 4G;
        keepalive_timeout 5;

        # Only requests to our Host are allowed
        if ( $http_host !~* ^%(domain)s$ ) {
            return 444;
        }

        # Block download user agents
        if ($http_user_agent ~* YoudaoBot|Sogou|YandexBot|linkdexbot|panscient) {
            return 403;
        }

        # path for static files
        root %(htdocs_dir)s;

        location / {
            try_files /themes/%(subdomain)s$uri /themes/%(subdomain)s$uri.html /themes/%(subdomain)s$uri/index.html $uri $uri.html $uri/index.html @forward_to_app;
        }

        location @forward_to_app {
            include       /etc/nginx/proxy_params;
            proxy_pass    http://proxy_%(subdomain)s;
        }

        error_page 500 501 502 503 504 505 506 507 508 510 511 /50x.html;
        location = /50x.html {
            ssi on;
            internal;
            auth_basic off;
            root %(htdocs_dir)s;
            try_files /themes/%(subdomain)s$uri $uri =404;
        }
}
