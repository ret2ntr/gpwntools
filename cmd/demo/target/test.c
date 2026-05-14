#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
void backdoor(){
	puts("win");
	system("/bin/bash");
}
void vuln(){
	write(1,"input >",7);
	char buf[0x30];
	read(0,buf,0x300);
	puts(buf);
}
int main(int argc,char *argv[]){
	vuln();
	return 0;
}
