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
#include <pthread.h>

#include "include/common.h"
#include "include/net.h"

void
start_service (void)
{
  start_syshandle();
}
