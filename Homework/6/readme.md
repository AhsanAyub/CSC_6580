## Structuring

### Part 1

Starting with the provided solution to the basic block homework, or with your own solution, apply the constructive proof of the structure theorem. We will do this in pieces. For next time:

1. Find the entry point and see if it appears the C runtime is in use. If so, figure out where main is and add it to the addresses to extract.

2. Create a Python class for a Node. There should be three types of Node, possibly by subclass.
  - A function node that holds a basic block that has a single next address or no next address ("unknown")
  - A predicate node that holds a basic block that has two next addresses, one for true and one for false
  - A label assignment node that holds an address to assign to the label

3. Package all basic blocks into Node instances.  Don't worry about the label assignments yet.


### Part 2

Now that you have the program and some basic data structures, create two new data structures:

- An if-then-else data structure that holds a basic block ending in true / false branching
- A sequence data structure that holds a series of (sequential) basic blocks.

Now for each basic block you found, create a prime (if-then-else or sequence).  Let the exit be label 0. For now treat any block that ends with an unknown destination as an exit.  Keep track of the number of times a label is referenced and, for any label referenced only once (except the entry point and the exit) substitute the label setting block with the corresponding prime.  Be careful to avoid an infinite recursion!

My solution to the previous assignment is attached.  Note that it has been refactored into multiple files.

Example output for an if-then-else containing sequences and label settings.

```
if
    lea rcx, [tax]
    jz 0x2132
then
    mov edi, 1
    jmp 0x214f
    L = 0x214f
else
    call 0x215a
    L = 0x214f
fi
```