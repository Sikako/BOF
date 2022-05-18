#include<stdio.h> 
#include<unistd.h> 

void shell(){
	   system("/bin/bash");
} 
void vuln(){
	   char buf[10]; 
           printf("hihi\n");  
	   gets(buf); 
} 
int main(){
	   vuln(); 
	   printf("you are stranger\n");
}

