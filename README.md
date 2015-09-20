# CTF
CTF Write-up repository

#CSA CTF 2015 Online Qualification Round
Reversing 200
The clue for this challenge was "We're getting a transmission from someone in the past, find out what he wants." and then provided a link to https://ctf.isis.poly.edu/static/uploads/b6d918a9bfa9e1ebf798ac7a78231b78/HackingTime_03e852ace386388eb88c39a02f88c773.nes
The clue about being from the past and the .nes file extension gave away the fact that it was an NES rom, although it also could have been verified with the 'file' command.
```
    file HackingTime_03e852ace386388eb88c39a02f88c773.nes 
    HackingTime_03e852ace386388eb88c39a02f88c773.nes: iNES ROM dump, 2x16k PRG, 1x8k CHR, [Vert.]
```

I had never dealt with NES rom hacking so I did a little digging and learned the FCEUX is the go to emulator due to its built in debugging tools.  After a cool little intro in the game, you get to a point where you need to enter a password.  The password can be up to 24 characters long and can be [A-Z,0-9]...36^24 combinations.    At this point I decided my thumbs would get a little sore trying to brute force it, so I opened the debugger and stepped in to the program.  I tried stepping in to the program to pause right when the password was being checked, but didn't have any luck, due to the way the controller's input is read.  Instead I switched tactics and used the RAM watcher to determine that the password was being stored in RAM starting at $0005 and set a break point for that address.  Success!
![image](http://i.imgur.com/62zeV37.png)
At this point, I was pretty confident I was looking at the code that determined if the password was correct.  It was time to make extensive use of https://en.wikibooks.org/wiki/6502_Assembly to figure out what the code was doing.
It only took me about 3 instructions before I got confused and had to consult http://nesdev.com/6502.txt to get a definition of the register flags and to understand that the ROL command used the carry flag register.
```
 00:82F5:85 3B     STA $003B = #$00
>00:82F7:B9 05 00  LDA $0005,Y @ $0005 = #$43
 00:82FA:AA        TAX
 00:82FB:2A        ROL
 00:82FC:8A        TXA
 00:82FD:2A        ROL
 00:82FE:AA        TAX
 00:82FF:2A        ROL
 00:8300:8A        TXA
 00:8301:2A        ROL
 00:8302:AA        TAX
 00:8303:2A        ROL
 00:8304:8A        TXA
 00:8305:2A        ROL
 00:8306:48        PHA
 00:8307:A5 3B     LDA $003B = #$00
 00:8309:AA        TAX
 00:830A:6A        ROR
 00:830B:8A        TXA
 00:830C:6A        ROR
 00:830D:AA        TAX
 00:830E:6A        ROR
 00:830F:8A        TXA
 00:8310:6A        ROR
 00:8311:85 3B     STA $003B = #$00
 00:8313:68        PLA
 00:8314:18        CLC
 00:8315:65 3B     ADC $003B = #$00
 00:8317:59 5E 95  EOR $955E,Y @ $955E = #$70
 00:831A:85 3B     STA $003B = #$00
 00:831C:AA        TAX
 00:831D:2A        ROL
 00:831E:8A        TXA
 00:831F:2A        ROL
 00:8320:AA        TAX
 00:8321:2A        ROL
 00:8322:8A        TXA
 00:8323:2A        ROL
 00:8324:AA        TAX
 00:8325:2A        ROL
 00:8326:8A        TXA
 00:8327:2A        ROL
 00:8328:AA        TAX
 00:8329:2A        ROL
 00:832A:8A        TXA
 00:832B:2A        ROL
 00:832C:59 76 95  EOR $9576,Y @ $9576 = #$20
 00:832F:99 1E 00  STA $001E,Y @ $001E = #$86
 00:8332:C8        INY
 00:8333:C0 18     CPY #$18
 00:8335:D0 C0     BNE $82F7
 00:8337:A0 00     LDY #$00
 00:8339:B9 1E 00  LDA $001E,Y @ $001E = #$86
 00:833C:D0 08     BNE $8346
 00:833E:C8        INY
 00:833F:C0 18     CPY #$18
 00:8341:D0 F6     BNE $8339
 00:8343:A9 01     LDA #$01
 00:8345:60        RTS -----------------------------------------
 00:8346:A9 00     LDA #$00
 00:8348:60        RTS -----------------------------------------
```
Noticing the RTS at the end of this section, I tried to do a trace to determine where I was called from/returning to.  I wasn't succesful at that, so hopefully I can tell what's going on just from this section.
The section of code from $82F7 and ending at $8306 takes the first letter of my entered password, ("C"/0x43), rotates it left 3 time and pushes the result (0x1A) on to the stack.
The next section from $8307 to $8311 does some memory manipulation on $003b and then stores the result back.  I'm not sure what $003b represents, but it's value was zero so I didn't need to analyze this section too closely.
Starting at $8313 we pull from the stack (0x1A).  Note: for some reason the debugger is saying taht $003b is 0x00 but ram watch/ram search is saying it contains 0x20.  Not sure why that is.
At $8317 we perform an XOR with $955E and Y.  Y has 0 and $955E contains 0x70.  For some reason, the result of this is 6A...not sure why.  The result (0x6A) is then stored to $003B.  
The next interesting comparison comes at $8333 where we commpare y to $0018.  $0018 is the 20th character in the password and the Y register contains 0x01 at the time of comparison.
It took me a while, but it finally dawned on me what the line:
```
>00:82F7:B9 05 00  LDA $0005,Y @ $0005 = #$43
```
was really doing.  This is what is used to check each letter in the guessed password, using what wikibooks describes as Absoluted Indexed with Y https://en.wikibooks.org/wiki/6502_Assembly#Absolute_Indexed_with_Y:_a.2Cy
With this new understanding, I set a breakpoint for $82F7 and started over with trying to understand how this fragment was checking the password.  It loops through this line to check every letter (keeping track of it in the Y register and checking it's value at $833F).  I set a breakpoint at $8343 so I could see what happens after the check is complete.
```
00:8333:C0 18     CPY #$18
 00:8335:D0 C0     BNE $82F7
>00:8337:A0 00     LDY #$00
 00:8339:B9 1E 00  LDA $001E,Y @ $0036 = #$42
 00:833C:D0 08     BNE $8346
 00:833E:C8        INY
 00:833F:C0 18     CPY #$18
 00:8341:D0 F6     BNE $8339
 00:8343:A9 01     LDA #$01
 00:8345:60        RTS -----------------------------------------
 ```
At $8339 we can see we're using the Absoluted Indexed with Y addressing mode again.  (The value starting at $001E is 0x86, so clearly it isn't just the unmodified ASCII stored there).
BNE is Branch on Result Not Zero, which is Branch if Z=0.  For a LDA, Z=1 IFF the memory address being loaded from is zero.  I decided to skip over the branch (by setting Z=1).  That allowed me to beat the game.  Unfortunately the message I Got said that 'They might use that password in other places that might lead to a score'.  Rats...looks like I need to actually find the password and not just skip over the code.  So, we know now that we want $001E-$003A to contain 0x00, so let's set a breakpoint for a write to $001E and see where we are writing to it.  The first break came at $832F.where it told me it was about to write 0x86 to 0x1e.  That number seems to be familiar.
The instruction at $832C is EOR $9576,Y.  I think my goal is to have this always be zero, so I set a breakpoint at $9576.  $9576 initially equals 0x20.  What value do I need to put in $0005 to make it be 0x20 after being modified?
I decided to track what the value of the Accumulator was at $832C based on the password entered.
I set my breakpoint and started testing passwords
Password|Accumulator
A A7
B 26
C A6
D 25
E A5
F 24
G A4
...
It didn't take too long to realize there was a pattern.  I set the first letter of the password to N and was happy to see that 001E contained 0x00 after running.  I copied down the values for the rest of the formula and the values in memory starting at $9576 and put together the password...and was wrong.
Unfortunately, the values are shifted based upon which spot in the password they are, so the values donn't hold across all spots, but the incrementing/decrementing pattern does.  Based on this, I was able to eventually crack the password, which was also the flag!

