#define HEAD404 "HTTP/1.1 404 Not Found\nConnection: Keep-alive\nKeep-Alive: timeout=5\nContent-Length: "
#define HEAD200 "HTTP/1.1 200 OK\nConnection: Keep-alive\nKeep-Alive: timeout=5\nContent-Length: "
#define HEAD202 "HTTP/1.1 200 OK\nConnection: Keep-alive\nKeep-Alive: timeout=5\nContent-Type: application/x-javascript\nContent-Length: "

/* HTTP Templanes names */
//#define JSTABLE "/jstable.js"
#define PAGE404 "/404.html"	// page template for 404 code
#define PAGEADMIN "/admin.html" // page template for /admin/
#define STATICDIR "/static/" // page template for /admin/

char *page404;
char *pageAdmin;

int init_pages(void);
void free_pages_buf(void);
int str_replace(char *output, char *input, char *sWhat, char *sWith);
