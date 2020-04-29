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


### Part 3

#### Reductions

Structuring code (so far) should already compose elements where there is a single reference.

For example, if you have the following items:

```
0xe0be:
if
    0x000000000000e0be: cmp rax, rbp
    0x000000000000e0c1: ja 0xe0b0
then
    L := 0xe0b0
else
    L := 0xe0c3
fi
0xe0c3:
0x000000000000e0c3: add rsp, 8
0x000000000000e0c7: pop rbx
0x000000000000e0c8: pop rbp
0x000000000000e0c9: ret
L := 0x0
```

Let's assume `0xe0c3` is referenced just once, in the above if-then-else.  In this case, we can move it into the else part and obtain the following.

```
0xe0be:
if
    0x000000000000e0be: cmp rax, rbp
    0x000000000000e0c1: ja 0xe0b0
then
    L := 0xe0b0
else
    0x000000000000e0c3: add rsp, 8
    0x000000000000e0c7: pop rbx
    0x000000000000e0c8: pop rbp
    0x000000000000e0c9: ret
    L := 0x0
fi
```

Now we have one subprogram instead of two, and we have eliminated one of the labels.  See the last section below for how to output this.

#### Graphs

Produce a graph of the remaining structured elements in the DOT format.  This is a simple format for representing graphs and digraphs.  You can read all about it at http://www.graphviz.org, but all you should really need to know is the following.

A digraph in the DOT language looks like the following.

```
digraph "/usr/bin/ls" {
  "0xe0be" -> "0xe0b0"
  "0xe0be" -> "0x0"
}
```

This is the segment of the graph for the last subprogram presented in the last section.  Nodes of the graph should be the addresses of the subprograms, and edges connect them.  As you can see from the example, you can put node names in quotation marks, and add a directed edge with an arrow (`->`).

In order for this to work, the node names must be consistent.  Use the `hex()` to format the addresses.  The graph name (here it is `/usr/bin/ls`) does not matter; you may name it whatever you wish.

#### Output

Name your (main) program `structure.py`.  It should take the same arguments as prior versions, but the output should be the following.

- A file named parts.lst that contains a listing of each structured part that remains after reduction.  So for the example in the prior section, the structure for `0xe0be` would be in there, but not `0xe0c3`, since it is now contained in 0xe0be.  Give the address, a colon, and then the listing.  Indentation is nice, but not required.  Skip a line between each structured part.
- A file named `graph.dot` that contains the connectivity graph of the remaining parts.
