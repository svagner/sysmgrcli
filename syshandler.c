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
#include <ifaddrs.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <openssl/md5.h>

#include "include/common.h"
#include "include/net.h"
#include "include/syscons.h"
#include "include/sysproto.h"

#define AUTHUSERLEN 20
#define AUTHPASSLEN 80

int client_sock;
Errors ErrCodes[] = {
	{ 0, "Complete", 0, 0 },
	{ 1, "Authorized failed", 0, 0},
	{ 2, "Data not valid", 0, 0},
};

void
get_system_info (void)
{
    struct utsname name;
    int i;

    uname(&name);

    memset(SInfo.serverName, 0, sizeof(SInfo.serverName));	
    memset(SInfo.OS, 0, sizeof(SInfo.OS));	
    memset(SInfo.ReleaseOS, 0, sizeof(SInfo.ReleaseOS));	
    strcpy(SInfo.serverName, name.nodename);	
    strcpy(SInfo.OS, name.sysname);	
    strcpy(SInfo.ReleaseOS, name.release);	
    SInfo.numHDD = get_hdd_info(SInfo.HardDrives);
};

void
get_system_ips (void)
{
	struct ifaddrs *ifaddr;
	int family, s;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return;
	}

	struct ifaddrs *ifa = ifaddr;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL)
		{
			int family = ifa->ifa_addr->sa_family;
			if (family == AF_INET || family == AF_INET6)
			{
				char ip_addr[NI_MAXHOST];
				int s = getnameinfo(ifa->ifa_addr,
						((family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6)),
						ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);
				if (s != 0)
				{
					printf("getnameinfo failed - can't determine our ip_interfaces");
					return;
				}
				else
				{
					/* add some processing here */
					printf("IP - %s",ip_addr);
				}
			}
		}
	}
	freeifaddrs(ifaddr);
};

static int
do_write (void)
{
  register int n, i;
  char *buffer;
  char *encbuffer;
  unsigned int packet_size = 0;

  //char auth_user[AUTHUSERLEN];
  char *auth_user;
  //char auth_pass[AUTHPASSLEN];
  char *auth_pass;
  unsigned char md5sum[MD5_DIGEST_LENGTH];
  get_system_info();

  auth_user = malloc(AUTHUSERLEN);
  auth_pass = malloc(AUTHPASSLEN);

  memset(auth_user, 0, AUTHUSERLEN);
  memset(auth_pass, 0, AUTHPASSLEN);

  strcpy(auth_user, configVar[6].value);
  strcpy(auth_pass, configVar[7].value);

  packet_size = AUTHUSERLEN+AUTHPASSLEN+sizeof(SInfo)+sizeof(struct HDDInfo)*MAXHDDS+4+sizeof(unsigned int);
  buffer = malloc(packet_size);
  memset(buffer, 0, sizeof(buffer));
  encbuffer = malloc(packet_size);
  memset(encbuffer, 0, sizeof(encbuffer));

  memcpy(buffer, auth_user, AUTHUSERLEN);
  memcpy(buffer+AUTHUSERLEN, auth_pass, AUTHPASSLEN);
  memcpy(buffer+AUTHUSERLEN+AUTHPASSLEN, (char *)&SInfo, sizeof(SInfo));
  for (i=0; i<MAXHDDS; i++)
  {
    memcpy(buffer+AUTHUSERLEN+AUTHPASSLEN+sizeof(SInfo)+i*sizeof(struct HDDInfo), (char *)SInfo.HardDrives[i], sizeof(struct HDDInfo));
  };
  DPRINT_ARGS("BUFFER: %s", buffer);
  DPRINT_ARGS("PACKET_SIZE: %ld", packet_size);
  //memset(md5sum, 0, MD5_DIGEST_LENGTH);
  get_MD5(md5sum, buffer, AUTHUSERLEN+AUTHPASSLEN+sizeof(SInfo)+sizeof(struct HDDInfo)*MAXHDDS);
  memcpy(encbuffer, &packet_size, sizeof(unsigned int));
  encrypt_decrypt(encbuffer + sizeof(unsigned int), buffer, AUTHUSERLEN+AUTHPASSLEN+sizeof(SInfo)+sizeof(struct HDDInfo)*MAXHDDS);
  free(buffer);

  n = write (client_sock, encbuffer, packet_size);

  free(encbuffer);
  free(auth_user);
  free(auth_pass);

  return n;

}

static void
//do_read (register struct kevent const *const kep)
do_read (void)
{
  enum { bufsize = 1024 };
  auto char buf[bufsize], tempbuf[bufsize];
  register int n;
  int ret;
  //register ecb *const ecbp = (ecb *) kep->udata;

  n = read (client_sock, &ret, sizeof(int));
  switch(ret)
  {
	  case 0: DPRINT("Connect complete!"); break;
	  case 1: ERROR_ARGS("%s", ErrCodes[ret].value); break;
	  case 2: ERROR_ARGS("%s", ErrCodes[ret].value); break;
	  default: ERROR("Answer from server not valid"); break;  	  
  }
//  ke_change (kep->ident, EVFILT_READ, EV_DISABLE, kep->udata);
//  ke_change (kep->ident, EVFILT_WRITE, EV_ENABLE, kep->udata);
}

static void
do_connect ()
{
  int result;
  struct sockaddr_in serv_addr;
  client_sock = 0;

  serv_addr.sin_addr.s_addr = inet_addr(configVar[1].value);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(atoi(configVar[2].value));

  DPRINT("DO_CONNECT!");
  if ((client_sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
	FATAL_ARGS("Error creating socket: %s", strerror (errno));
  if ((result=connect(client_sock,&serv_addr,sizeof(struct sockaddr_in))) < 0) 
  {
	  ERROR_ARGS("Error in connect(): %s", strerror (errno));
  };
};

static void event_loop (register int const kq)
    __attribute__ ((__noreturn__));

static void
event_loop (register int const kq)
{
	struct kevent change;    /* event we want to monitor */
	struct kevent event;

	  EV_SET(&change, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, atoi(configVar[8].value), 0);


  for (;;)
    {
      register int n,i;

      n = kevent (kq, &change, 1, &event, 1, NULL);
//      ke_vec_used = 0;  /* Already processed all changes.  */

      if (n == -1)
        FATAL_ARGS("Error in kevent(): %s", strerror (errno));
      if (n == 0)
      {
        NOTICE("No events received!");
      }
      DPRINT_ARGS("NUM EVENT: %d FILTER: %d FLAGS: %d", n, change.filter, change.flags);

      for (i = 0; i < n; ++i)
      {
	int res=0;
		if((res=do_write())<0)
		{
			close(client_sock);
			do_connect();
		}
		else
		{
//			do_read();
		};
		DPRINT_ARGS("RESULT: %d", res);
        }

    }
};

void
get_static_info(void)
{
  char *sysinfo;
  int num = 0, i;

  /* Get MotherBoard Info */
  sysinfo = malloc(MAXBOARDINFO);
  memset(sysinfo, 0, MAXBOARDINFO);
  dmidecode_main(sysinfo, 1, "baseboard-manufacturer");
  if (strlen(sysinfo)<1)
	  dmidecode_main(sysinfo, 1, "system-manufacturer");
  strcat(SInfo.Board, sysinfo);
  strcat(SInfo.Board, " ");

  memset(sysinfo, 0, MAXBOARDINFO);
  dmidecode_main(sysinfo, 1, "baseboard-product-name");
  if (strlen(sysinfo)<1)
	  dmidecode_main(sysinfo, 1, "system-product-name");
  strcat(SInfo.Board, sysinfo);
  free(sysinfo);
  DPRINT_ARGS("Motherboard: %s", SInfo.Board);

  /* Get CPU Info */
  memset(SInfo.CPU, 0, sizeof(SInfo.CPU));
  sysinfo = malloc(MAXCPUINFO);
  memset(sysinfo, 0, MAXCPUINFO);
  num = dmidecode_main(sysinfo, 0, "processor-version");
  memset(sysinfo, 0, MAXCPUINFO);
  SInfo.numCPU = num;
  for (i = 1; i <= SInfo.numCPU; i++)
  {
    num = dmidecode_main(sysinfo, i, "processor-version");
    strcat(SInfo.CPU[num-1], sysinfo);
    strcat(SInfo.CPU[num-1], " ");
  };

  num = 0;
  memset(sysinfo, 0, MAXCPUINFO);
  num = dmidecode_main(sysinfo, 0, "processor-frequency");
  memset(sysinfo, 0, MAXCPUINFO);
  for (i = 1; i <= SInfo.numCPU; i++)
  {
    num = dmidecode_main(sysinfo, i, "processor-frequency");
    strcat(SInfo.CPU[num-1], sysinfo);
  };
  free(sysinfo);
  for (i = 0; i < SInfo.numCPU; i++)
  {
    DPRINT_ARGS("CPU Info: Count: %d Model: %s", SInfo.numCPU, SInfo.CPU[i]);
  };

  int mib[2];
  size_t len;
  len = 2;
  sysctlnametomib("hw.physmem", mib, &len);
  len = sizeof(SInfo.memory);
  if (sysctl(mib, 2, &SInfo.memory, &len, NULL, 0) == -1)
        ERROR_ARGS("sysctl hw.physmem not access! %s", strerror(errno));
//  printf("%ld\n", SInfo.memory);
};

void 
start_syshandle(void)
{
  register int kq, i;


  if ((kq = kqueue ()) == -1)
	FATAL_ARGS("Error creating kqueue: %s", strerror (errno));

    for (i=0; i<MAXHDDS; i++)
    {
	    SInfo.HardDrives[i] = malloc(sizeof(struct HDDInfo));
    };
  get_static_info();
  do_connect();
  event_loop (kq);
};
