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

I had never dealt with NES rom hacking so I did a little digging and learned the FCEUX is the go to emulator due to its built in debugging tools.  After a cool little intro in the game, you get to a point where you need to enter a password.  The password can be up to 24 characters long and can be [A-Z,0-9]...36^24 combinations.    At this point I decided my thumbs would get a little sore trying to brute force it, so I opened the debugger and stepped in to the program.  I had a hard time determining what the program was doing, so I entered a password guess in, and paused the program just before finishing entering the password.  I then started the Trace Logger, started the program, finished the password and paused the program/stopped the trace logger.  The trace had repeated code which I think had something to do with the polling to see if the user had pressed the button to submit the password.  I removed these lines to make the output more readable.

 
