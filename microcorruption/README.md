#Embedded Security Microcorruption writeups
##Level 0/Tutorial
Looking quickly at the program, I see a call to get_password and then a call to
check_password.  After check_password, r15 is tested with failure msg being
printed if r15 is zero.
I ran the program and broke on check_password.
###check_password analysis

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

##Level 1/New Orleans
