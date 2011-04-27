#!/usr/bin/env python
# encoding: utf-8
"""
   do_audit is a small script to create hashes from web applications in a jboss
   server for audit purposes. 
"""
from email.mime.text import MIMEText
import hashlib
import os
# for hostname
import platform
# email facilities
import smtplib
import stat
# time convertions
import time
# logging facilities
import logging
import logging.handlers


def sha1(_filename):
  """Returns the sha1 of the file received"""
  if os.path.isfile(_filename):
    return hashlib.sha1(open(_filename).read()).hexdigest()
  else:
    return "Cannot hash file: " + _filename

def md5(_filename):
  """Returns the md5 of the file received"""
  if os.path.isfile(_filename):
    return hashlib.md5(open(_filename).read()).hexdigest()
  else:
    return "Cannot hash file: " + _filename

def get_fileinfo(_filename):
  """Returns the file size in bytes and the Last modified attribute"""
  if os.path.isfile(_filename):
    file_stats = os.stat(_filename)
    file_info = {
      'fsize': file_stats [stat.ST_SIZE],
      'f_lm': time.strftime("%Y%m%d-%H:%M",time.localtime(file_stats[stat.ST_MTIME])),
      'f_ct': time.strftime("%Y%m%d-%H:%M",time.localtime(file_stats[stat.ST_CTIME]))
    }
  return 'Size=%(fsize)s LastMod=%(f_lm)s' % file_info

#This is where we setup which instances (jboss profiles) we are going to be monitoring
audited_instances = [
'APPSRV1',
'APPSRV2',
'APPSRV3',
'APPSRV4'
]

# these are the default locations but we want to be able to change this
jboss_basedir = '/srv/jboss-eap/server'
deployment_directory = 'theappdir'
# we only audit war files but we could audit more than that
audited_extensions = ['war']
host = platform.node()


my_logger = logging.getLogger(host)
my_logger.setLevel(logging.INFO)
# We setup the logging host
handler_syslog = logging.handlers.SysLogHandler(address=('syslogserver', 514))
my_logger.addHandler(handler_syslog)

period = time.strftime("%Y%m" , time.localtime())
tmp_email = []

for instance in audited_instances:
  print instance
  fullsrvdir = os.path.join(jboss_basedir, instance, deployment_directory)
  for root, dirs, files in os.walk(fullsrvdir):
    for f in files:
      if f[-3:].lower() in audited_extensions:
        filename = os.path.join(root, f)
        msg = "APPAUDIT Host=%s Instance=%s Period=%s Artifact=%s %s SHA1=%s MD5=%s" % \
          (host, instance, period, f, get_fileinfo(filename), sha1(filename), md5(filename))
        print msg
        # now we submit the log line to splunk or the syslog server
        my_logger.info(msg)
        tmp_email.append("%s\n" % (msg))

# We setup the email settings
email_from = "auditor@server.name"
email_to = "feniix@server.name" 
# we do unauthenticated smtp delivery
email_server = "smtp.server.name" 

# and we build the email
email = MIMEText(''.join(tmp_email))
email['Subject'] = "App Audit - %s %s %s" % (time.strftime("%Y %B", time.localtime()), 
                                             period, host)
email['From'] = email_from
email['To'] = email_to

# and we send the email
s = smtplib.SMTP(email_server)
s.sendmail(email_from, email_to, email.as_string())
s.close()

