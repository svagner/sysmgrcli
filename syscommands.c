#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "include/syscmds.h"
#include "include/common.h"

#define CMDNFOUND "Command not found. Call [help] please.\r\n"


int 
help_cmd (char *arg, char *outbuf) {
    char help[] = "show help...";
    char *delim = " ";
    char *buf;
    char final[1024];
    int i;

    if (arg==NULL)	
    {	    
	memcpy(outbuf, help, strlen(help));
	return strlen(help);
    };
    buf = strtok(arg, delim);
    if (strcmp(buf, "help"))
    {
	    memcpy(outbuf, CMDNFOUND, strlen(CMDNFOUND));
	    return strlen(CMDNFOUND);
    }
    while(buf!=NULL)
    {
	buf = strtok(NULL, delim);
	if (buf==NULL)
	{
	    sprintf(final, "Usage commands:\n");	
	    for	(i=0; i<sizeof(commands)/sizeof(*commands); i++)
	    {	    
		strcat(final, "\t\t");
		strcat(final, commands[i].name);    
		strcat(final, "\n\0");
	    };
	    memcpy(outbuf, final, strlen(final));
	    return strlen(final);
	}
	else
	    memcpy(outbuf, "\r", 1);	
	    return 1;
	    break;
    };
    memcpy(outbuf, arg, strlen(arg));
    return strlen(arg);
}

int
show_cmd (char *arg, char *outbuf) {
    char help[] = "please, input 'help show'";
    if (arg==NULL)	
    {	    
	memcpy(outbuf, help, strlen(help));
	return strlen(help);
    };
    
    memcpy(outbuf, arg, strlen(arg));
    return strlen(arg);
};

int
parse_incomming(char *buf, char *outbuf, int bufsize, int *retcount)
{
	char *p;
		    DPRINT_ARGS("INPUT: %s", buf);		

	if (buf[0] == 4 && bufsize == 1)
	    return -1;

	if (buf[0]==EOF || bufsize==0)
	    return 0;
	if (buf[0] == '\r' || buf[0]=='\n' || (buf[0] == '\r' && buf[1]=='\n'))
	{
	    buf[1]='\0';
	    return 0;
	}
	if((p = strchr(buf, '\r'))) *p =0;
	char *cmd, *tmp;
	int i, result;
	tmp = xmalloc(bufsize, "in_buffer");
	bzero(tmp, bufsize);

	if((bufsize-1)>0)
	memcpy(tmp, buf, bufsize-1);

	
	for (i=0; i<sizeof(commands)/sizeof(*commands); i++)
	{
	//	    DPRINT_ARGS("char1: '%c' char2: '%c'", tmp[0], commands[i].name);		
		    DPRINT_ARGS("COMAPARE %s with %s", tmp, commands[i].name);		
		if ((cmd = strstr(tmp, commands[i].name)))
		{
		    DPRINT_ARGS("tmp: %s", tmp);		
		    result = commands[i].function(tmp, outbuf);
		    xfree(tmp);
		    return result;
		};
	};
	xfree(tmp);
	memcpy(outbuf, CMDNFOUND, strlen(CMDNFOUND));
	return strlen(CMDNFOUND);
};
