# Embedded Security Microcorruption writeups
## Level 0/Tutorial
Looking quickly at the program, I see a call to get_password and then a call to
check_password.  After check_password, r15 is tested with failure msg being
printed if r15 is zero.
I ran the program and broke on check_password.
### check_password analysis

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
python: print '\x45\x4f\x71\x58\x7e\x47\x75' -- EOqX~Gu
I tried that and that was the code!

## Level 2/Sydney

