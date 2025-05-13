# temp config to fetch letsencrypt certificates for %(subdomain)s
#
# The HTTPS section is necessary because the load-balancer will redirect
# all HTTP requests to HTTPS.

server {
        listen          80;
        server_name     %(top_domain)s %(domain)s;

        access_log %(LOCALSTATEDIR)s/log/nginx/%(domain)s-access.log main;
        error_log  %(LOCALSTATEDIR)s/log/nginx/%(domain)s-error.log;

        # Only requests to our Host are allowed
        if ($http_host !~* ^.*\.%(top_domain)s$ ) {
            return 444;
        }

        root %(htdocs_dir)s/%(subdomain)s;

        location / {
            try_files $uri =404;
        }
}

server {
        listen       443 ssl;
        server_name  %(domain)s;

        access_log %(LOCALSTATEDIR)s/log/nginx/%(domain)s-access.log main;
        error_log  %(LOCALSTATEDIR)s/log/nginx/%(domain)s-error.log;

        ssl_certificate      /etc/pki/tls/certs/live/djaoapp.com/fullchain.pem;
        ssl_certificate_key  /etc/pki/tls/certs/live/djaoapp.com/privkey.pem;
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
        root %(htdocs_dir)s/%(subdomain)s;

        location / {
            try_files $uri =404;
        }
}
