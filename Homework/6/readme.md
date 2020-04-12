## Structuring


### Part 1

Starting with the provided solution to the basic block homework, or with your own solution, apply the constructive proof of the structure theorem. We will do this in pieces. For next time:

1. Find the entry point and see if it appears the C runtime is in use.  If so, figure out where main is and add it to the addresses to extract.

2. Create a Python class for a Node. There should be three types of Node, possibly by subclass.
  1. A function node that holds a basic block that has a single next address or no next address ("unknown")
  2. A predicate node that holds a basic block that has two next addresses, one for true and one for false
  3. A label assignment node that holds an address to assign to the label

3. Package all basic blocks into Node instances.  Don't worry about the label assignments yet.