# separate %(appname)s logging in a separate file
$template rawMsgFormat,"%msg%\n"

if $programname == '%(appname)s' then /var/log/gunicorn/%(appname)s-app.log; rawMsgFormat

