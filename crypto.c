#include <openssl/rc4.h> 
#include <openssl/md5.h>
#include <stdio.h> 
#include <unistd.h> 
#include "include/ssl.h"

int 
encrypt_decrypt (void *bufcrypt, void* buffer, int sizeOfBuf) 
{ 
    RC4_KEY key; 
    RC4_set_key(&key,sizeof(PASSSOLT),(const unsigned char *)PASSSOLT);  
    RC4(&key,sizeOfBuf,buffer,bufcrypt); 
    return 0;
}

int 
get_MD5(unsigned char *md5sum, void *buffer, int sizeOfBuf)
{
    MD5_CTX md5handler;
    MD5((unsigned char *) buffer, sizeOfBuf, (unsigned char *)md5sum);
    return 0;
}
