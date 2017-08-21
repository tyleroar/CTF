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
Ok, so getsn(0x30, 0x43ee) and then test_password_valid(0x43ee) this means I
control memory from 0x43ee to 0x441d.  At the end of login, the retaddr is
stored at 0x43fe (note the add 0x10 sp on 0x453a).  This means we can jump to
any arbitrary location in code we want by entering 16 characters and then our
return address (in little endian).  unlock_door (0x4446) looks like a good place to go
to, so I entered AAAAAAAAAAAAAAAAFD and the door unlocked.

### Level 4 / Reykjavik

