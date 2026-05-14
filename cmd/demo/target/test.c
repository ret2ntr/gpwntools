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
}
int main(int argc,char *argv[]){
	char buf[0x30];
	puts("input your name >");
	read(0,buf,0x30);
	printf(buf);
	vuln();
	return 0;
}
