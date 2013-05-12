#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "include/common.h"
#include "include/config.h"

#define MAXVARLEN   25
#define READFBUF    1024

int
all_digits (register char const *const s)
{
	register char const *r;

	for (r = s; *r; r++)
		if (!isdigit (*r))
			return 0;
	return 1;
}

int
check_options(void)
{
	int nopt,i;
	int error=0;
	nopt = sizeof(configVar)/sizeof(*configVar);
	for (i=0; i<nopt; i++)
	{
		switch(configVar[i].id) {
			case 1: if (!configVar[i].isset) error=1; break;
			case 2: if (!configVar[i].isset) error=1; break;
			case 3: if (!configVar[i].isset) error=1; break;
			case 4: if (!configVar[i].isset) error=1; break;
			default: break;                 
		}
	};
	return error;
}

void
parse_config (void) {
    FILE *confDesc;
    char *delim = "#";
    char *brtk;
    char *result = NULL;
    char val[MAXVALLEN], var[MAXVARNAME], rbuf[READFBUF];
    register int numvar, numline=0;
    register int varnum, i, compare=0;

    varnum = sizeof(configVar)/sizeof(*configVar);

    if((confDesc = fopen(configFile, "r"))==NULL)
	    fatal("Config file \"%s\": %s", configFile, strerror(errno));
    
    while (!feof(confDesc))
    {
	if(fgets(rbuf, READFBUF, confDesc))
	{
	    numline++;    
	    if (rbuf[0]=='#' || rbuf[0]=='\n')
		    continue;
	    result = strtok(rbuf, delim);
	    if ((numvar=sscanf(result, "%[^ ^\t^\n^=] = %[^\t^\n]", var, val))!=2)
		    FATAL_ARGS("Parse config \"%s\" error at line %d", configFile, numline);
	    for(i=0; i<varnum; i++)
		    if (!strcmp(var, configVar[i].name))
		    {
			if (all_digits (val) && configVar[i].type == STRING)
			    FATAL_ARGS("Parse config \"%s\" error at line %d. Variable \"%s\" isn't set correct.", configFile, numline, var);    
			if (!all_digits (val) && configVar[i].type == DIGIT)
			    FATAL_ARGS("Parse config \"%s\" error at line %d. Variable \"%s\" isn't set correct.", configFile, numline, var);    
			strcpy((char *)&configVar[i].value, val); configVar[i].isset=1;
			compare++;
			continue;
		    };
	    if (!compare)
		FATAL_ARGS("Parse config \"%s\" error at line %d. Variable \"%s\" not found.", configFile, numline, var);
	    compare = 0;
	    bzero(var, sizeof(var));
	    bzero(val, sizeof(val));

	    continue;
	}
    };
#ifdef DEBUG
    DPRINT("config file:");
    for(i=0; i<varnum; i++)
    {	
	    if (configVar[i].type==DIGIT)
	    DPRINT_ARGS("%s: %d", configVar[i].name, atoi(configVar[i].value));
	    if (configVar[i].type==STRING)
	    DPRINT_ARGS("%s: %s", configVar[i].name, configVar[i].value);
    }
#endif

    fclose(confDesc);
};
