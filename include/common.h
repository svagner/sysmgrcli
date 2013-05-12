#pragma once
#include <sys/queue.h>
#include <sys/param.h>
#include <stdio.h>

#define ERROR_ARGS(fmt, ...) do { error("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__, __VA_ARGS__); } while (0)
#define ERROR(fmt) do { error("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__); } while (0)
#define FATAL_ARGS(fmt, ...) do { fatal("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__, __VA_ARGS__); } while (0)
#define FATAL(fmt) do { fatal("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__); } while (0)
#define NOTICE_ARGS(fmt, ...) do { notice("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__, __VA_ARGS__); } while (0)
#define NOTICE(fmt) do { notice("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__); } while (0)
#ifdef DEBUG
#define DPRINT_ARGS(fmt, ...) do { debug("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__, __VA_ARGS__); } while (0)
#define DPRINT(fmt) do { debug("[%s +%d] %s(): " fmt, __FILE__, \
			    __LINE__, __func__); } while (0)
#else
#define DPRINT(fmt)
#define DPRINT_ARGS(fmt, ...)
#endif

#define _WITH_DPRINTF

#define DIGIT	0x11
#define STRING	0x01
#define MAXVALLEN   256
#define MAXVARNAME  25
#define MAXLENMD5   16

/* HTTP Templanes names 
#define JSTABLE "/jstable.js"
#define PAGE404 "/404.html"
#define PAGEADMIN "/admin.html"*/

struct config {
	char *logfile;
	char *admhost;
	int admport;
	char *syshost;
	int sysport;
};

typedef struct configDescr {
	int id;
	char name[MAXVARNAME];
	int type;
	int isset;
	char value[MAXVALLEN];
} configD;

struct passwd *userstruct;

char const *pname;
char const *pidFile;
char const *configFile;
struct pidfh *pidf;
int logfd;

extern configD configVar[];

/* main functions */
void usage (register char *const progname);
void sigcatch(int sig);

/* logging */
void vlog (char const *const fmt, va_list ap);
void fatal (char const *const fmt, ...);
void error (char const *const fmt, ...);
void notice (char const *const fmt, ...);
void debug (char const *const fmt, ...);

/* config parse */
int check_options(void);
void parse_config (void);
int all_digits (register char const *const s);
int all_digits (register char const *const s);

/* net lib */
void start_service (void);

/* memcontrol */
LIST_HEAD(xmemctl_head, xmemctl) memctl;
struct xmemctl_head *memctl_headp;

struct xmemctl 
{
    void *ptr;	
    long long size;
    char label[20];
    LIST_ENTRY(xmemctl) xmemctl_list;
};

void *xmalloc (register unsigned long const size, char *label);
void xfree (void *ptr);
void xfree_all (void);
void *xrealloc (void *ptr, register unsigned long const size);

char template_path[MAXVALLEN]; // path for http tamplate
int dmidecode_main(char *buffer, int num, char *query);
int parse_opt_string(const char *arg);
int get_MD5(char *md5sum, void *buffer, int sizeOfBuf);
int encrypt_decrypt (void *bufcrypt, void* buffer, int sizeOfBuf);
