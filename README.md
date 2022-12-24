## Logserver

```
1. В вагранте поднимаем 2 машины web и log
2. На web поднимаем nginx
3. На log настраиваем центральный лог сервер на любой системе на выбор
   * journald;
   * rsyslog;
   * elk.
4. Настраиваем аудит, следящий за изменением конфигов нжинкса
   Все критичные логи с web должны собираться и локально и удаленно.
   Все логи с nginx должны уходить на удаленный сервер (локально только критичные).
   Логи аудита должны также уходить на удаленную систему.
Формат сдачи ДЗ - vagrant + ansible
* развернуть еще машину elk
* таким образом настроить 2 центральных лог системы elk и какую либо еще;
* в elk должны уходить только логи нжинкса;
* во вторую систему все остальное.
```
### 1. Основная часть задания

* Подготовлен [Vagrantfile файл](Vagrantfile) и [скрипт ansible](provision.yml), которые выполнят настройку и установку всего необходимого автоматически.

* Клонируем репозиторий: `git clone https://github.com/mmmex/logserver.git`

* Выполняем вход в директорию: `cd logserver`

* Запускаем `vagrant`: `vagrant up`

Будет развернуто две ВМ `log` (192.168.56.2) и `web` (192.168.56.3).

### WEB

* На `web` поднят `nginx`([роль install-nginx](roles/install-nginx/tasks/main.yml)):

```bash
[root@web ~]# systemctl status nginx.service 
● nginx.service - The nginx HTTP and reverse proxy server
   Loaded: loaded (/usr/lib/systemd/system/nginx.service; disabled; vendor preset: disabled)
   Active: active (running) since Fri 2022-12-23 17:26:08 UTC; 3h 28min ago
  Process: 5407 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
  Process: 5404 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
  Process: 5403 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
 Main PID: 5409 (nginx)
   CGroup: /system.slice/nginx.service
           ├─5409 nginx: master process /usr/sbin/nginx
           └─5412 nginx: worker process

Dec 23 17:26:08 web systemd[1]: Starting The nginx HTTP and reverse proxy server...
Dec 23 17:26:08 web nginx[5404]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Dec 23 17:26:08 web nginx[5404]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Dec 23 17:26:08 web systemd[1]: Started The nginx HTTP and reverse proxy server.
[root@web ~]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 52:54:00:4d:77:d3 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global noprefixroute dynamic eth0
       valid_lft 69064sec preferred_lft 69064sec
    inet6 fe80::5054:ff:fe4d:77d3/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:9e:74:84 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.3/24 brd 192.168.56.255 scope global noprefixroute eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe9e:7484/64 scope link 
       valid_lft forever preferred_lft forever
```

* Настроен сервис `audit`, который будет следить за изменением конфигурационных файлов `nginx`, а именно: папки `/etc/nginx`, `/etc/nginx/conf.d` и `/etc/nginx/default.d`([роль audit-client](/roles/audit-client/tasks/main.yml)):

```bash
[root@web ~]# auditctl -l
-w /etc/nginx/conf.d -p wa -k filesystem
-w /etc/nginx/default.d -p wa -k filesystem
-w /etc/nginx -p wa -k filesystem
```

#### Проверка:

1. Запишем в конец файла `nginx.conf` какой-нибудь текст:

```bash
[root@web ~]# echo '#test' >> /etc/nginx/nginx.conf
```

2. Проверим, какое событие зафиксировал сервис `audit` на локальном хосте:

```bash
[root@web ~]# ausearch -f /etc/nginx/nginx.conf
----
time->Sat Dec 24 01:28:22 2022
type=PROCTITLE msg=audit(1671834502.689:2227): proctitle="-bash"
type=PATH msg=audit(1671834502.689:2227): item=1 name="/etc/nginx/nginx.conf" inode=67522344 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PATH msg=audit(1671834502.689:2227): item=0 name="/etc/nginx/" inode=85 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=CWD msg=audit(1671834502.689:2227):  cwd="/root"
type=SYSCALL msg=audit(1671834502.689:2227): arch=c000003e syscall=2 success=yes exit=3 a0=8262c0 a1=441 a2=1b6 a3=fffffff0 items=2 ppid=5696 pid=5698 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="filesystem"
```

3. Проверим тоже на центральном лог сервере `log`:

```bash
$ vagrant ssh log
Last login: Sat Dec 24 01:40:00 2022 from 10.0.2.2
[vagrant@log ~]$ sudo -i
[root@log ~]# ausearch -f nginx.conf
---
time->Sat Dec 24 01:28:22 2022
node=web type=PROCTITLE msg=audit(1671834502.689:2227): proctitle="-bash"
node=web type=PATH msg=audit(1671834502.689:2227): item=1 name="/etc/nginx/nginx.conf" inode=67522344 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
node=web type=PATH msg=audit(1671834502.689:2227): item=0 name="/etc/nginx/" inode=85 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:httpd_config_t:s0 objtype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
node=web type=CWD msg=audit(1671834502.689:2227):  cwd="/root"
node=web type=SYSCALL msg=audit(1671834502.689:2227): arch=c000003e syscall=2 success=yes exit=3 a0=8262c0 a1=441 a2=1b6 a3=fffffff0 items=2 ppid=5696 pid=5698 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="filesystem"
```





* Все логи с ВМ `web` будут собираться локально и удаленно сервисом `journald` в пассивном режиме ([роль journald-client](/roles/journald-client/tasks/main.yml)).

```bash
[root@web ~]# cat /etc/systemd/journal-upload.conf
[Upload]
URL=http://log:19532
# ServerKeyFile=/etc/ssl/private/journal-upload.pem
# ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
# TrustedCertificateFile=/etc/ssl/ca/trusted.pem
```

#### Проверка:

1. На ВМ `web` выполним команду, которая запишет в лог 3 сообщения (info,warning,crit) и проверим журнал:

```bash
[root@web ~]# logger -p info This is info 
[root@web ~]# logger -p warning This is warning
[root@web ~]# logger -p crit This is critical
[root@web ~]# journalctl -p 6 | grep This
Dec 24 01:50:15 web vagrant[25440]: This is info
Dec 24 01:50:27 web vagrant[25441]: This is warning
Dec 24 01:50:40 web vagrant[25443]: This is critical
```

2. Проверяем наличие сообщений на центральном лог сервере `log`:

```bash
[root@log ~]# journalctl -D /var/log/journal/remote -p 6 | grep This
Dec 24 01:50:15 web vagrant[25440]: This is info
Dec 24 01:50:27 web vagrant[25441]: This is warning
Dec 24 01:50:40 web vagrant[25443]: This is critical
```





* Все логи `nginx` уходят на удаленный сервер (локально храняться только критичные)([роль install-nginx](/roles/install-nginx/tasks/main.yml)):

```bash
[root@web ~]# grep -E '^access_log.*|^error_log.*|ansible' /etc/nginx/nginx.conf
### Managed by ansible! ###
access_log syslog:server=unix:/dev/log,facility=local7,tag=nginx,severity=info main;
error_log /var/log/nginx/error.log;
error_log syslog:server=unix:/dev/log,facility=local6,tag=nginx_error;
### Managed by ansible! ###
```

* К сожалению, `journald` не может фильтровать сообщения на входе, он просто регистрирует все события, и далее инструментом `journalctl` мы фильтруем вывод. Обычный пользователь не имеет прав доступа к инструменту `journalctl` (как и к /var/log/messages), поэтому я буду фильтровать запись в лог-файл `/var/log/messages` добавив  правило фильтрации для всех сообщений `nginx` в `/etc/rsyslog.conf`([роль rsyslog-config](/roles/rsyslog-config/tasks/main.yml)):

```bash
[root@web ~]# grep -E 'ansible|web nginx:' /etc/rsyslog.conf
### Managed by ansible! ###
:msg, contains, "web nginx:" ~
### Managed by ansible! ###
```

#### Проверка:

1. Отправим два запроса, один на страничку по умолчанию, второй на несуществующую на web-сервер `nginx`, что вызовет записи `info` и `crit` события в лог:

```bash
[root@web ~]# curl -I http://web
HTTP/1.1 200 OK
Server: nginx/1.20.1
Date: Fri, 23 Dec 2022 23:29:47 GMT
Content-Type: text/html
Content-Length: 4833
Last-Modified: Fri, 16 May 2014 15:12:48 GMT
Connection: keep-alive
ETag: "53762af0-12e1"
Accept-Ranges: bytes
[root@web ~]# curl -I http://web/test.php
HTTP/1.1 404 Not Found
Server: nginx/1.20.1
Date: Fri, 23 Dec 2022 23:33:10 GMT
Content-Type: text/html
Content-Length: 3650
Connection: keep-alive
ETag: "636d2d22-e42"
```

2. Проверяем события в логах локально:

```bash
[root@web ~]# cat /var/log/messages | grep 'web nginx: 127.0.0.1'
[root@web ~]# cat /var/log/messages | grep 'web nginx_error:'
Dec 23 23:28:44 web journal: web nginx_error: 2022/12/23 23:28:44 [error] 5412#5412: *5 open() "/usr/share/nginx/html/test.php" failed (2: No such file or directory), client: 127.0.0.1, server: _, request: "HEAD /test.php HTTP/1.1", host: "web"
Dec 23 23:33:10 web journal: web nginx_error: 2022/12/23 23:33:10 [error] 5412#5412: *7 open() "/usr/share/nginx/html/test.php" failed (2: No such file or directory), client: 127.0.0.1, server: _, request: "HEAD /test.php HTTP/1.1", host: "web"
```

3. Проверяем на центральном лог сервере:

```bash
[root@log ~]# journalctl -D /var/log/journal/remote -u nginx     
-- Logs begin at Fri 2022-12-23 20:20:32 MSK, end at Sat 2022-12-24 02:33:10 MSK. --
Dec 23 20:26:08 web systemd[1]: Starting The nginx HTTP and reverse proxy server...
Dec 23 20:26:08 web nginx[5404]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Dec 23 20:26:08 web nginx[5404]: nginx: configuration file /etc/nginx/nginx.conf test is successful
Dec 23 20:26:08 web systemd[1]: Started The nginx HTTP and reverse proxy server.
Dec 24 02:29:47 web nginx[5412]: web nginx: 127.0.0.1 - - [23/Dec/2022:23:29:47 +0000] "HEAD / HTTP/1.1" 200 0 "-" "curl/7.29.0" "-"
Dec 24 02:33:10 web nginx[5412]: web nginx_error: 2022/12/23 23:33:10 [error] 5412#5412: *7 open() "/usr/share/nginx/html/test.php" failed (2: No such file or directory), client: 127.0.0.1, server: _, request: "HEAD /test.php HTTP/1.1", h
Dec 24 02:33:10 web nginx[5412]: web nginx: 127.0.0.1 - - [23/Dec/2022:23:33:10 +0000] "HEAD /test.php HTTP/1.1" 404 0 "-" "curl/7.29.0" "-"
```







* Логи службы `audit` также уходят на центральную систему лог сервера ([роль audit-client](/roles/audit-client/tasks/main.yml)).

```bash
[root@web ~]# cat /etc/audisp/plugins.d/au-remote.conf

# This file controls the audispd data path to the
# remote event logger. This plugin will send events to
# a remote machine (Central Logger).

active = yes
direction = out
path = /sbin/audisp-remote
type = always
#args =
format = string
```

### LOG

* В качестве центрального лог сервера настроен `journald` по протоколу `http` ([роль journald-server](/roles/journald-server/tasks/main.yml)):

```bash
[root@log ~]# cat /usr/lib/systemd/system/systemd-journal-remote.service
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Journal Remote Sink Service
Requires=systemd-journal-remote.socket

[Service]
ExecStart=/usr/lib/systemd/systemd-journal-remote \
          --listen-http=-3 \
          --output=/var/log/journal/remote/
User=systemd-journal-remote
Group=systemd-journal-remote
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
WatchdogSec=10min

[Install]
Also=systemd-journal-remote.socket
[root@log ~]# cat /etc/systemd/journal-upload.conf
[Upload]
URL=http://localhost:19532
# ServerKeyFile=/etc/ssl/private/journal-upload.pem
# ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
# TrustedCertificateFile=/etc/ssl/ca/trusted.pem
```

* Настроен сервис `audit` для приема сообщений от клиентов ([роль audit-server](/roles/audit-server/tasks/main.yml)):

```bash
[root@log ~]# cat /etc/audit/auditd.conf
#
# This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
```