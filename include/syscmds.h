/* Commands */
int show_cmd(char *arg, char *outbuf);
int help_cmd(char *arg, char *outbuf);

/* functions */
//char *parse_incomming(void *, char *);

typedef struct CMDS {
	int id;
	char *name;
	int (*function) ( char *arg, char *outbuf );
	char *description;
	int parent;
} _commands;

_commands commands[2] = {
	{ 0, "show", show_cmd, "Show values for variables.", -1 },
	{ 1, "help", help_cmd, "Show help via commands.", -1 },
//	{ 2, "show", show_help, "Help for show statement", 1 },
//	{ 3, "managers", NULL, "", 0 },
};


