# separate %(appname)s logging in a separate file

template(name="rawMsgFormat" type="string" string="%msg%\n")

if $programname == '%(appname)s' then action(type="omfile" file="/var/log/gunicorn/%(appname)s-app.log" template="rawMsgFormat")
