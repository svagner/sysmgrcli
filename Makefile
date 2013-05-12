.include <bsd.own.mk>

PROG=   sysmgrcli
MAN=    sysmgr.1
SRCS=    syscommands.c syshandler.c memcontrol.c logger.c conf.c netapi.c sysmgrcli.c dmiopt.c dmidecode.c dmiutil.c dmioem.c camcontrol.c crypto.c 
CFLAGS+= -ggdb -Iinclude -lutil -lc -lpthread -L/usr/local/lib/ -lssl
#CFLAGS+= -DDEBUG -DDEBUGMALLOC
DPADD=	${LIBCAM} ${LIBSBUF} ${LIBUTIL}
LDADD=	-lcam -lsbuf -lutil

.include <bsd.prog.mk>
