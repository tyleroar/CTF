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
 
