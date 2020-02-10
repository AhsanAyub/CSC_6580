## Binary Math

Modify the `binary.asm` program to take exactly two integer command line arguments (you can parse these with `atol` from the standard C library). Print the sum and difference of the two numbers as follows.

```
$ ./addsub 957897396 765765
Adding:
0000 0000 0000 0000 0000 0000 0000 0000 0011 1001 0001 1000 0101 1010 1011 0100 
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 1011 1010 1111 0100 0101 
0000 0000 0000 0000 0000 0000 0000 0000 0011 1001 0010 0100 0000 1001 1111 1001 
Subtracting:
0000 0000 0000 0000 0000 0000 0000 0000 0011 1001 0001 1000 0101 1010 1011 0100 
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 1011 1010 1111 0100 0101 
0000 0000 0000 0000 0000 0000 0000 0000 0011 1001 0000 1100 1010 1011 0110 1111
```

Note that `puts` and `atol` do not require 16-byte alignment. Call your program `addsub.asm`. If there are not exactly two arguments, give an error message.

```
./addsub 957897396 765765 9870974
Expected exactly two integer arguments.
```

Make sure your program ends with an appropriate return value, and that you include the command to build it as a comment on the first line.