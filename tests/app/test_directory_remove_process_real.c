#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc,char **argv)
{
    if(argc!=5) abort();
    char self[4096]; ssize_t n=readlink("/proc/self/exe",self,sizeof self-1);
    if(n<=0 || n>=(ssize_t)sizeof self-1) abort();
    self[n]=0;
    char server[4096]; memcpy(server,self,(size_t)n+1);
    char *slash=strrchr(server,'/'); if(!slash) abort();
    size_t prefix=(size_t)(slash-server)+1;
    if(prefix+sizeof "vireo-auth-server">sizeof server) abort();
    memcpy(server+prefix,"vireo-auth-server",sizeof "vireo-auth-server");
    execlp("python3","python3",VIREO_AUTH_PROCESS_TEST_SCRIPT,"--real",server,self,
        argv[1],argv[2],argv[3],argv[4],(char *)NULL);
    abort();
}
