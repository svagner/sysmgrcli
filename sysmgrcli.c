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
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/param.h>
#include <libutil.h>

#include "include/common.h"
#include "include/net.h"

void
usage (register char *const progname)
{
    ERROR_ARGS("Usage: %s -c <config file> -p <pid file>\n", progname);
    exit(1);

}

void 
sigcatch(int sig)
{
    switch(sig)
    {
	case SIGTERM: 
		NOTICE("Get signal SIGTERM. Exiting..."); 
		xfree_all();
		exit(0);
		break;
	case SIGINT: 
		NOTICE("Get signal SIGINT. Exiting..."); 
		xfree_all();
		exit(0);
		break;
	default: break;
    }
}

int
daemonize() 
{
    pid_t pid;

    pidf = pidfile_open(pidFile, 0666, &pid);
    if (pidf == NULL) {
	if (errno == EEXIST) {
	    FATAL_ARGS("Daemon already running, pid: %d.", (int)pid);
	}
	FATAL("Cannot open or create pidfile");
    }

    userstruct = getpwnam(configVar[3].value);

    setuid(userstruct->pw_uid);
    setgid(userstruct->pw_gid);

    pid = fork();
    switch(pid) {
	case 0:
	    setsid();
	    chdir("/");
	    close(0);
	    close(1);
	    close(2);
	    pidfile_write(pidf);
        case -1:
	    perror("Error: unable to fork");
	    break;
	default:
	    fprintf(stderr, "Starting daemon. Pid %d\n", pid);
	    exit(0);
	    break;
	}
    return 0;
}

int
main (register int const argc, register char *const argv[])
{
    register int optch;
    auto int one = 1;
    register int option_errors = 0;
    struct xmemctl *xmctl;

    pname = strrchr (argv[0], '/');
    pname = pname ? pname+1 : argv[0];
    if (argc < 4)
	 usage (argv[0]);

    signal(SIGTERM, sigcatch);
    signal(SIGINT, sigcatch);
    signal(SIGPIPE, SIG_IGN);

    

    while ((optch = getopt (argc, argv, "c:p:")) != EOF)
    {
	switch (optch)
        {
	    case 'p':
		if (strlen (optarg) == 0)
		{
		    ERROR_ARGS("Invalid argument for -p option: %s", optarg);
		    option_errors++;
		}
		pidFile = optarg;
		break;
	    case 'c':
		if (strlen (optarg) == 0)
		{
		    ERROR_ARGS("Invalid argument for -c option: %s", optarg);
		    option_errors++;
		}
		configFile = optarg;
		break;
	    default:
		ERROR_ARGS("Invalid option: -%c", optch);
		option_errors++;
        }
    }

    if (option_errors || optind != argc)
	usage (argv[0]);

    parse_config();
    if (check_options()!=0)
	FATAL("Parametrs in config is not setted. Exiting...");

    if (configVar[0].isset)
	    if((logfd = open(configVar[0].value, O_WRONLY|O_APPEND))<0)
		    ERROR_ARGS("Log file \"%s\": %s", configVar[0].value, strerror);
    if (configVar[5].isset && atoi(configVar[5].value)==1)
	if (daemonize())
	    FATAL("Can't daemonize. Exiting...");
    LIST_INIT(&memctl);
    LIST_INIT(&adminAccessCtl);
    start_service();

    pidfile_close(pidf);
    pidfile_remove(pidf);
    close(logfd);

}
