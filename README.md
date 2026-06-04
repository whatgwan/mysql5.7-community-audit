# mysql5.7-community-audit

**Lightweight audit-log plugin for MySQL 5.7 Community Edition** — logins, failed
logins, `GRANT`/`REVOKE`, and DDL — written to a file, for the case where
MariaDB's `server_audit` won't load and MySQL Enterprise Audit isn't an option.

Built and tested on **MySQL 5.7.44** (the final 5.7 release). ~150 lines of C,
compiled from source against *your* server's headers, and **fail-safe** (a fault
in the plugin disables auditing, it never takes the database down).

> The plugin loads as `login_audit` (the loadable name / `.so` / system variable).

---

## Why this exists

MySQL 5.7 **Community Edition has no working free audit plugin**:

- **MariaDB `server_audit`** — the usual suggestion — does **not** work on Oracle
  MySQL 5.7.44:
  - 10.5+ builds fail to load: `undefined symbol: psi_prlock_wrlock` (a
    MariaDB-internal symbol Oracle MySQL doesn't export).
  - 10.2–10.4 builds load, then **SIGSEGV on the first connection** inside
    `get_db_mysql57` — [**MDEV-25498**](https://jira.mariadb.org/browse/MDEV-25498).
    They read MySQL's private `THD` at a hardcoded offset that's wrong for this
    build. *Every* MariaDB build shares that code path, so no version fixes it.
- **MySQL Enterprise Audit** is a commercial add-on (not in Community).

Both `server_audit` failures are the same root cause: **a binary built for a
different server**. This plugin avoids them by being compiled against **your
exact MySQL headers** (so symbols resolve) and using only the **public audit
event API** (`plugin_audit.h`) — it never touches `THD`, so there is no offset
to get wrong, and nothing to SIGSEGV.

If you got here by Googling `psi_prlock_wrlock`, `get_db_mysql57`, or
`MDEV-25498` while trying to audit MySQL Community — this is for you.

## What it captures

| Class | Events | Fields |
|---|---|---|
| `CONNECTION` | successful logins, **failed logins**, `CHANGE_USER` | user, priv_user, host, ip, conn_id, status |
| `GENERAL` | **DCL** (`GRANT`/`REVOKE`/`CREATE`·`ALTER`·`DROP`·`RENAME USER`/`SET PASSWORD`) and **DDL** (`CREATE`/`ALTER`/`DROP`/`TRUNCATE`/`RENAME` of schema objects), including attempts | command, user, host, ip, thread_id, query |

Statement-level (it records that a statement ran, with who/where — not row
values). DML/`SELECT` are intentionally **not** logged.

Example output:

```
2026-06-04T10:55:41 event=CONNECT status=SUCCESS conn_id=2  user=root priv_user=root host=localhost ip= db=
2026-06-04T11:04:57 event=CONNECT status=FAIL    conn_id=65 user=app  priv_user=app  host= ip=10.0.0.9 db=
2026-06-04T11:20:03 event=STMT cmd=create_user err=0 thread_id=88 user=admin host=10.0.0.5 ip=10.0.0.5 query=CREATE USER 'x'@'%' IDENTIFIED BY <secret>
```

Password statements (`CREATE USER … IDENTIFIED BY …`, `SET PASSWORD`) are
**redacted** by MySQL's statement rewriting before the plugin ever sees them.

## Requirements

- **MySQL 5.7 Community** (audit interface `0x0401`, stable across 5.7.x ≈5.7.9+).
  Tested on **5.7.44**. *Not* MySQL 8.0 (its audit API differs).
- A C++ compiler and the **matching** `mysql-community-devel` headers.
- Build on a toolchain whose glibc is **≤** the server's (i.e. same OS family as
  your server) so the `.so` is ABI-compatible.

## Build

```bash
# Install build tools + the dev headers MATCHING your server version
#   (example: EL7 / MySQL 5.7.44)
yum install -y gcc-c++ mysql-community-devel-5.7.44     # or your distro equivalent

# my_sqlcommand.h is vendored here (GPLv2, from the MySQL source): the devel
# package omits it, but the audit structs reference enum_sql_command.
g++ -Wall -fPIC -shared -DMYSQL_DYNAMIC_PLUGIN -DMYSQL_ABI_CHECK \
    -I. -I/usr/include -I/usr/include/mysql \
    -o login_audit.so login_audit.c
```

`-DMYSQL_ABI_CHECK` skips `plugin.h`'s optional plugin-service includes (which
pull server-source-only headers this plugin doesn't use). A successful build
exports the plugin ABI symbols:

```bash
nm -D login_audit.so | grep _mysql_plugin_interface_version_   # must print a match
```

## Install

```bash
cp login_audit.so "$(mysql -N -e 'SELECT @@plugin_dir')/"
mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql   # must be writable by the mysql user
```

Load it via config (so it starts with the server and can't be silently
runtime-uninstalled):

```ini
[mysqld]
plugin-load-add  = login_audit=login_audit.so
login_audit_file = /var/log/mysql/login_audit.log
```

Restart MySQL, then verify:

```sql
SELECT PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME='login_audit';
-- ACTIVE
```

Quick functional test:

```sql
CREATE USER 'audit_canary'@'localhost' IDENTIFIED BY 'x';   -- event=STMT cmd=create_user
DROP USER 'audit_canary'@'localhost';                       -- event=STMT cmd=drop_user
-- then a wrong-password login -> event=CONNECT status=FAIL
```

## Fail-safe design

The plugin runs inside `mysqld`, so it is written to **fail safe**. On any error
it can detect — log file won't open, a write fails (e.g. disk full), or the
server hands it no event — it trips a circuit breaker and goes **dormant**: it
stops auditing, logs one line to the error log, and never risks the server.
Inputs from the server are null- and length-checked; `init` never blocks startup.

in-process C cannot be made immune to its *own* memory bugs — a
SIGSEGV can't be safely caught inside `mysqld`. The defense is that the code is
tiny, uses only the public event structs, and guards every field. Read it before
you run it.

## Notes for replicated / Group Replication setups

- File output means the plugin is **inert to replication** (no tables, no binlog,
  no GTIDs). Safe on every node.
- **Install it on every node.** DCL/DDL is captured where the statement
  *executes* — i.e. on the **primary**. A read-only replica logs its connections
  but won't show replicated DCL/DDL (no client runs it there). On failover the
  new primary must already have the plugin, or you have a gap.

## Operational / compliance notes

- **The local file is a buffer, not the system of record.** A privileged user can
  edit or delete it. For an audit *trail*, ship it off-box in near-real-time to an
  append-only/WORM destination they can't alter, and **alert on the stream going
  quiet** (the plugin can be `UNINSTALL`-ed or go dormant — detect the silence).
- Rotate the local file with `logrotate`; size it so nothing is dropped before
  it's shipped.
- The log contains usernames, source hosts/IPs, and DDL/DCL statement text —
  treat it as sensitive.
- MySQL 5.7 is **end-of-life** (Oct 2023). This plugin audits it; it does not make
  it supported.

## License

GPLv2 — it links the MySQL plugin headers. `my_sqlcommand.h` is included verbatim
from the MySQL source (GPLv2).

## Contributing

Issues and PRs welcome. Keep the plugin small, total, and dependency-free — the
safety argument depends on it.
