#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/event.h>
#include <sys/time.h>

#define _WITH_DPRINTF

#include "include/common.h"

static struct tm *t_m;
static time_t t;

void
vlog (char const *const fmt, va_list ap)
{
    vdprintf (logfd?logfd:2, fmt, ap);
    dprintf (logfd?logfd:2, "\n");
}

void fatal (char const *const fmt, ...)
    __attribute__ ((__noreturn__));

void
fatal (char const *const fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);

//  dprintf (logfd?logfd:2, "%s: ", pname);
  t=time(NULL);
  t_m=localtime(&t);
  dprintf (logfd?logfd:2, "%02d:%02d:%02d [FATAL]", t_m->tm_hour, t_m->tm_min, t_m->tm_sec);
  vlog (fmt, ap);
  va_end (ap);
  exit (1);
}

void
error (char const *const fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
//  dprintf (logfd?logfd:2, "%s: ", pname);
  t=time(NULL);
  t_m=localtime(&t);
  dprintf (logfd?logfd:2, "%02d:%02d:%02d [ERROR]", t_m->tm_hour, t_m->tm_min, t_m->tm_sec);
  vlog (fmt, ap);
  va_end (ap);
}

void
notice (char const *const fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  t=time(NULL);
  t_m=localtime(&t);
  dprintf (logfd?logfd:2, "%02d:%02d:%02d [NOTICE]", t_m->tm_hour, t_m->tm_min, t_m->tm_sec);
  vlog (fmt, ap);
  va_end (ap);
}

void
debug (char const *const fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  t=time(NULL);
  t_m=localtime(&t);
  dprintf (logfd?logfd:2, "%02d:%02d:%02d [DEBUG]", t_m->tm_hour, t_m->tm_min, t_m->tm_sec);
  vlog (fmt, ap);
  va_end (ap);
}
