#define MAXVARNAME  25

configD configVar[] = {
	{ 0, "logfile", STRING, 0, 0 },
	{ 1, "master_host", STRING, 0, 0 },
	{ 2, "master_port", DIGIT, 0, 0 },
	{ 3, "daemon_uid", STRING, 0, 0 },
	{ 4, "daemon_gid", STRING, 0, 0 },
	{ 5, "is_daemon", DIGIT, 0, 0 },
	{ 6, "master_login", STRING, 0, 0 },
	{ 7, "master_password", STRING, 0, 0 },
	{ 8, "alive_timeout", DIGIT, 0, 0 },
};
