filter f_%(appname)s { program("gunicorn.%(appname)s.app"); };

destination d_%(appname)s { file("/var/log/gunicorn/%(appname)s-app.log"); };

log { source(s_sys); filter(f_%(appname)s); destination(d_%(appname)s); };
