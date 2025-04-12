filter f_docker { program("docker") or tags("docker"); };
filter f_5xxERR-hook { filter(f_docker) and message("HTTP\/.{3,20}[[:space:]]5[[:digit:]]{2}[[:space:]]"); };

destination d_docker { file("/var/log/docker.log"); };
destination d_5xxERR-hook {
    program("/usr/local/bin/logrotate-hook", keep-alive(yes));
};

log { source(s_sys); filter(f_docker); destination(d_docker); };
log { source(s_sys); filter(f_5xxERR-hook); destination(d_5xxERR-hook); };
