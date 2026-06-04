/*
  login_audit — minimal, DEFENSIVE MySQL 5.7 audit plugin.

  Captures the privileged-action trail MySQL 5.7 Community can't produce safely:
    * CONNECTION class : successful + failed logins, CHANGE_USER
    * GENERAL    class : DCL + DDL statements, with user/host/ip attribution
  Output is a flat file, so it is inert to Group Replication.

  Uses only the public audit event structs (plugin_audit.h) — never reads THD —
  so it is ABI-safe when compiled against the matching server headers.

  a SIGSEGV cannot be safely caught and resumed inside mysqld. The defense is
  therefore minimal/total code + the null and length guards below + the breaker
  + a never-fatal init + review and testing. Keep this file small and boring.
*/
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>

#define MAX_FIELD 4096          /* cap any single logged field: bounds output and
                                   guards against a bogus length from a bad event */

static char            *audit_file_path;
static FILE            *audit_fp       = NULL;
static pthread_mutex_t  audit_lock;
static volatile int     audit_disabled = 0; 

static MYSQL_SYSVAR_STR(file, audit_file_path,
  PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
  "Path to the login/privileged-action audit log file.",
  NULL, NULL, "/var/log/mysql/login_audit.log");

static struct st_mysql_sys_var *audit_sysvars[] = { MYSQL_SYSVAR(file), NULL };

static void audit_disable(const char *why)
{
  if (!audit_disabled)
  {
    audit_disabled = 1;
    fprintf(stderr,
            "login_audit: auditing DISABLED (plugin dormant, server unaffected): %s\n",
            why ? why : "unknown");
  }
}

/* timestamped, mutex-guarded append; trips the breaker on any write failure */
static void audit_write(const char *fmt, ...)
{
  char ts[32];
  time_t now;
  struct tm tmv;
  va_list ap;

  now = time(NULL);
  if (localtime_r(&now, &tmv) == NULL) { audit_disable("localtime_r failed"); return; }
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);

  pthread_mutex_lock(&audit_lock);
  if (audit_fp && !audit_disabled)
  {
    fprintf(audit_fp, "%s ", ts);
    va_start(ap, fmt);
    vfprintf(audit_fp, fmt, ap);
    va_end(ap);
    fputc('\n', audit_fp);
    if (fflush(audit_fp) != 0 || ferror(audit_fp))
    {
      clearerr(audit_fp);
      audit_disable("write/flush error on audit log");   
    }
  }
  pthread_mutex_unlock(&audit_lock);
}

#define CS(x) (int)((x).length > MAX_FIELD ? MAX_FIELD : (x).length), (x).str ? (x).str : ""

static int is_privileged_sql(const MYSQL_LEX_CSTRING *c)
{
  const char *s;
  if (c == NULL) return 0;
  s = c->str;
  if (s == NULL || c->length == 0) return 0;
  if (!strncasecmp(s, "create_", 7) || !strncasecmp(s, "alter_", 6) ||
      !strncasecmp(s, "drop_", 5)   || !strncasecmp(s, "rename_", 7) ||
      !strncasecmp(s, "truncate", 8))
    return 1;
  if (!strncasecmp(s, "grant", 5) || !strncasecmp(s, "revoke", 6) ||
      !strncasecmp(s, "set_password", 12))
    return 1;
  return 0;
}

static int audit_notify(MYSQL_THD thd MY_ATTRIBUTE((unused)),
                        mysql_event_class_t event_class, const void *event)
{
  /* Fail-safe: do nothing if dormant or if the server handed us no data. */
  if (audit_disabled || event == NULL)
    return 0;

  if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
  {
    const struct mysql_event_connection *e =
        (const struct mysql_event_connection *) event;
    const char *action;
    switch (e->event_subclass)
    {
      case MYSQL_AUDIT_CONNECTION_CONNECT:     action = "CONNECT";     break;
      case MYSQL_AUDIT_CONNECTION_CHANGE_USER: action = "CHANGE_USER"; break;
      default: return 0;
    }
    audit_write("event=%s status=%s conn_id=%lu user=%.*s priv_user=%.*s "
                "host=%.*s ip=%.*s db=%.*s",
                action, e->status == 0 ? "SUCCESS" : "FAIL", e->connection_id,
                CS(e->user), CS(e->priv_user), CS(e->host), CS(e->ip),
                CS(e->database));
    return 0;
  }

  if (event_class == MYSQL_AUDIT_GENERAL_CLASS)
  {
    const struct mysql_event_general *g =
        (const struct mysql_event_general *) event;
    if (g->event_subclass != MYSQL_AUDIT_GENERAL_LOG) return 0;
    if (!is_privileged_sql(&g->general_sql_command)) return 0;
    audit_write("event=STMT cmd=%.*s err=%d thread_id=%lu user=%.*s "
                "host=%.*s ip=%.*s query=%.*s",
                CS(g->general_sql_command), g->general_error_code,
                g->general_thread_id, CS(g->general_user), CS(g->general_host),
                CS(g->general_ip), CS(g->general_query));
    return 0;
  }
  return 0;
}

static int login_audit_init(MYSQL_PLUGIN p MY_ATTRIBUTE((unused)))
{
  pthread_mutex_init(&audit_lock, NULL);
  audit_fp = fopen(audit_file_path, "a");
  if (!audit_fp)
    audit_disable("cannot open audit log file for append");
  return 0;
}

static int login_audit_deinit(MYSQL_PLUGIN p MY_ATTRIBUTE((unused)))
{
  if (audit_fp) { fclose(audit_fp); audit_fp = NULL; }
  pthread_mutex_destroy(&audit_lock);
  return 0;
}

static struct st_mysql_audit audit_descriptor =
{
  MYSQL_AUDIT_INTERFACE_VERSION,
  NULL,
  audit_notify,
  { (unsigned long) MYSQL_AUDIT_GENERAL_LOG,
    (unsigned long) MYSQL_AUDIT_CONNECTION_ALL,
    0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

mysql_declare_plugin(login_audit)
{
  MYSQL_AUDIT_PLUGIN,
  &audit_descriptor,
  "login_audit",
  "Community",
  "Connection + DCL/DDL audit to file (MySQL 5.7), kind of fail-safe",
  PLUGIN_LICENSE_GPL,
  login_audit_init,
  login_audit_deinit,
  0x0001,
  NULL,
  audit_sysvars,
  NULL,
  0
}
mysql_declare_plugin_end;
