# Copyright (c) 2023, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import unicode_literals

import os

from . import (modify_config, modify_ini_config, postinst, stage_dir,
    stage_file, SetupTemplate)


class jenkinsSetup(SetupTemplate):

    jetty_home = '/usr/share/jetty'
    jenkins_home = '/usr/share/jetty/.jenkins'
    webdefault_conf_path = '/usr/share/java/jetty/etc'

    webdefault_config_template = """<?xml version="1.0" encoding="UTF-8"?>
<web-app
   xmlns="http://xmlns.jcp.org/xml/ns/javaee"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
   metadata-complete="false"
   version="3.1">
  <description>
    Default web.xml file. This file is applied to a Web application
    before it's own WEB_INF/web.xml file
  </description>
  <listener>
   <listener-class>org.eclipse.jetty.servlet.listener.ELContextCleaner</listener-class>
  </listener>
  <listener>
   <listener-class>org.eclipse.jetty.servlet.listener.IntrospectorCleaner</listener-class>
  </listener>
  <servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.eclipse.jetty.servlet.DefaultServlet</servlet-class>
    <init-param>
      <param-name>aliases</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>acceptRanges</param-name>
      <param-value>true</param-value>
    </init-param>
    <init-param>
      <param-name>dirAllowed</param-name>
      <param-value>true</param-value>
    </init-param>
    <init-param>
      <param-name>welcomeServlets</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>redirectWelcome</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>maxCacheSize</param-name>
      <param-value>256000000</param-value>
    </init-param>
    <init-param>
      <param-name>maxCachedFileSize</param-name>
      <param-value>200000000</param-value>
    </init-param>
    <init-param>
      <param-name>maxCachedFiles</param-name>
      <param-value>2048</param-value>
    </init-param>
    <init-param>
      <param-name>gzip</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>etags</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>useFileMappedBuffer</param-name>
      <param-value>true</param-value>
    </init-param>
    <load-on-startup>0</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>default</servlet-name>
    <url-pattern>/</url-pattern>
  </servlet-mapping>
  <servlet id="jsp">
    <servlet-name>jsp</servlet-name>
    <servlet-class>org.eclipse.jetty.jsp.JettyJspServlet</servlet-class>
    <init-param>
      <param-name>logVerbosityLevel</param-name>
      <param-value>DEBUG</param-value>
    </init-param>
    <init-param>
      <param-name>fork</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>xpoweredBy</param-name>
      <param-value>false</param-value>
    </init-param>
    <init-param>
      <param-name>compilerTargetVM</param-name>
      <param-value>1.7</param-value>
    </init-param>
    <init-param>
      <param-name>compilerSourceVM</param-name>
      <param-value>1.7</param-value>
    </init-param>
    <load-on-startup>0</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.jsp</url-pattern>
    <url-pattern>*.jspf</url-pattern>
    <url-pattern>*.jspx</url-pattern>
    <url-pattern>*.xsp</url-pattern>
    <url-pattern>*.JSP</url-pattern>
    <url-pattern>*.JSPF</url-pattern>
    <url-pattern>*.JSPX</url-pattern>
    <url-pattern>*.XSP</url-pattern>
  </servlet-mapping>
  <session-config>
    <session-timeout>30</session-timeout>
  </session-config>
  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
  <locale-encoding-mapping-list>
    <locale-encoding-mapping>
      <locale>ar</locale>
      <encoding>ISO-8859-6</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>be</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>bg</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>ca</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>cs</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>da</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>de</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>el</locale>
      <encoding>ISO-8859-7</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>en</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>es</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>et</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>fi</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>fr</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>hr</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>hu</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>is</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>it</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>iw</locale>
      <encoding>ISO-8859-8</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>ja</locale>
      <encoding>Shift_JIS</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>ko</locale>
      <encoding>EUC-KR</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>lt</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>lv</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>mk</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>nl</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>no</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>pl</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>pt</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>ro</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>ru</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sh</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sk</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sl</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sq</locale>
      <encoding>ISO-8859-2</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sr</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>sv</locale>
      <encoding>ISO-8859-1</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>tr</locale>
      <encoding>ISO-8859-9</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>uk</locale>
      <encoding>ISO-8859-5</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>zh</locale>
      <encoding>GB2312</encoding>
    </locale-encoding-mapping>
    <locale-encoding-mapping>
      <locale>zh_TW</locale>
      <encoding>Big5</encoding>
    </locale-encoding-mapping>
  </locale-encoding-mapping-list>
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Disable TRACE</web-resource-name>
      <url-pattern>/</url-pattern>
      <http-method>TRACE</http-method>
    </web-resource-collection>
    <auth-constraint/>
  </security-constraint>
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Enable everything but TRACE</web-resource-name>
      <url-pattern>/</url-pattern>
      <http-method-omission>TRACE</http-method-omission>
    </web-resource-collection>
  </security-constraint>
</web-app>
"""

    context_config_template = """<?xml version="1.0"  encoding="ISO-8859-1"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "http://www.eclipse.org/jetty/configure.dtd">
<Configure class="org.eclipse.jetty.webapp.WebAppContext">
  <Set name="contextPath">/%(webapp)s</Set>
  <Set name="war"><SystemProperty name="jetty.base" default="."/>/webapps/%(webapp)s.war</Set>
  <Set name="extractWAR">true</Set>
  <Set name="copyWebDir">false</Set>
  <Set name="defaultsDescriptor"><SystemProperty name="jetty.base" default="."/>/etc/webdefault.xml</Set>
  <Get name="securityHandler">
    <Set name="loginService">
      <New class="org.eclipse.jetty.security.HashLoginService">
        <Set name="name">%(webapp)s Realm</Set>
        <Set name="config"><SystemProperty name="jetty.base" default="."/>/etc/realm.properties</Set>
      </New>
    </Set>
    <Set name="authenticator">
      <New class="org.eclipse.jetty.security.authentication.FormAuthenticator">
        <Set name="alwaysSaveUri">true</Set>
      </New>
    </Set>
    <Set name="checkWelcomeFiles">true</Set>
  </Get>
</Configure>
"""

    jenkins_te_config_template = """
module jenkins 1.0;

require {
        type httpd_t;
        type hadoop_namenode_port_t;
        type unreserved_port_t;
        class tcp_socket name_bind;
        type var_t;
        type httpd_cache_t;
        class file { open read write relabelfrom relabelto getattr execute };
}

#============= httpd_t ==============
allow httpd_t httpd_cache_t:file { relabelfrom relabelto execute };
allow httpd_t var_t:file { open read getattr };
allow httpd_t hadoop_namenode_port_t:tcp_socket name_bind;
allow httpd_t unreserved_port_t:tcp_socket name_bind;
"""

    def __init__(self, name, files, **kwargs):
        super(jenkinsSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['jetty']
        self.configfiles = []

    def run(self, context):
        complete = super(jenkinsSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        # Workarounds to get jetty started (webdefault.xml and command line
        # arguments)
        _, new_webdefault_conf = stage_file(
            self.webdefault_conf_path, context=context)
        with open(new_webdefault_conf, 'w') as webdefault_conf_file:
            webdefault_conf_file.write(self.webdefault_config_template)
        modify_config(os.path.join(self.jetty_home, 'modules/jsp.mod'),
            settings={
                '-Dorg.apache.jasper.compiler.disablejsr199': 'true'
            }, sep='=', context=context)


        # Configure jetty/jenkins (environment variables and security context)
        jenkins_default_path = os.path.join(
            context.value('etcDir'), 'default', 'jenkins')
        modify_config(jenkins_default_path,
            settings={
                'JENKINS_HOME': self.jenkins_home,
                'HUDSON_HOME': self.jenkins_home
            }, sep='=', context=context)
        modify_ini_config('/usr/lib/systemd/system/jetty.service',
            settings={'Service':
                {'EnvironmentFile': '-%s' % jenkins_default_path}},
            context=context)
        _, new_context_conf = stage_file(
            os.path.join(self.jetty_home, 'webapps', 'jenkins.xml'),
            context=context)
        with open(new_context_conf, 'w') as context_conf_file:
            context_conf_file.write(
                self.context_config_template % {'webapp': 'jenkins'})
        stage_dir('/var/jenkins/jobs', context)

        jenkins_jobs_dir = os.path.join(self.jenkins_home, 'jobs')
        postinst.shell_command([
            '[', '-d', jenkins_jobs_dir, ']',
            '&&', 'mv', jenkins_jobs_dir,
            os.path.join(self.jenkins_home, 'jobs.prev')])
        postinst.shell_command([
            'cd', self.jenkins_home,
            '&&', 'ln', '-s', '/var/jenkins/jobs'])

        # Configure SELinux to allow jetty/jenkins jobs.
        jenkins_te = os.path.join(
            os.path.dirname(postinst.postinst_run_path), 'jenkins.te')
        with open(jenkins_te, 'w') as jenkins_te_file:
            jenkins_te_file.write(self.jenkins_te_config_template)
        postinst.install_selinux_module(jenkins_te,
            comment="Configure SELinux to allow jetty/jenkins jobs.")
        postinst.shell_command(
            ['setsebool', '-P', 'httpd_execmem', '1'])
        postinst.shell_command(
            ['setsebool', '-P', 'httpd_builtin_scripting', '1'])

        return complete
