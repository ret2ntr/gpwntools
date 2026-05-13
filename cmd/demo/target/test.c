#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc,char *argv[]){
	write(1,"hello\n",6);
	char buf[0x30];
	read(0,buf,0x300);
	return 0;
}
