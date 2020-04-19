#!/usr/bin/env python3
#

'''Declare node classes for structuring code.'''


from capstone import CsInsn
from disassembler import InstructionTests
from typing import List


# Amount to indent at each level.
INDENT = 4

# Name of the label variable.
LABELVAR = 'L'


class BasicBlock(object):
    '''A class to hold a basic block.'''

    def __init__(self):
        '''Create an empty basic block.'''
        self.instructions = []
        self.address = 0
        self.next = 0

    def __str__(self) -> str:
        '''Generate a string representation.'''
        return hex(self.address) + ': ' + '; '.join(self.instructions)

    def add(self, insn: CsInsn):
        '''Add an instruction to the end of the basic block.'''
        if self.address == 0:
            self.address = insn.address
        self.instructions.append(insn)
        self.next = insn.address + insn.size

    def get_instructions(self):
        '''Get the instructions in this basic block.'''
        return self.instructions

    def print(self, indent:int = 0):
        '''Print out the basic block at the specified indentation depth.'''
        for insn in self.instructions:
            print(' '*indent + f'0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}')

    def get_address(self) -> int:
        '''Get the starting address of the basic block.'''
        return self.address

    def get_next(self) -> int:
        '''Get the next address after this basic block.
        Note: this is not necessarily the next address in the flow!
        '''
        return self.next


class Node(object):
    '''The base class for all nodes.'''
    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.
        Subclasses must implement this.
        '''
        pass

    def get_basic_block(self) -> BasicBlock:
        '''Get the basic block in this node, if any.  If there
        is none, an empty basic block is returned.'''
        return BasicBlock()


class LabelNode(Node):
    '''A node that holds an assignment to the label and nothing
    else.
    '''
    def __init__(self, address: int):
        '''Make a node setting the label to the given address.'''
        self.address = address

    def __str__(self) -> str:
        '''Generate a string representation.'''
        return LABELVAR + ' := ' + hex(self.address)

    def get_value(self) -> int:
        '''Get the value of the label.'''
        return self.address

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        print(' '*indent + f'{LABELVAR} := 0x{self.address:016x}')


class FunctionNode(Node):
    '''A function node has a single entry and single exit, and
    performs some function.
    
    Essentially a function node holds a basic block with no
    branching or jumps, except possibly an unconditional jump
    at the end.
    '''

    def __init__(self, bb: BasicBlock, next: int):
        '''Make a function node.'''
        self.bb = bb
        self.next = next

    def get_basic_block(self) -> BasicBlock:
        return self.bb

    def get_next(self) -> int:
        '''Get the next address in the flow.'''
        return self.next

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        self.bb.print(indent)


class PredicateNode(Node):
    '''A predicate node has a single entry and two exits.

    Essentially a predicate node holds a basic block with
    no branching or loops, except for a conditional branch
    at the final instruction.
    '''

    def __init__(self, bb: BasicBlock, true: int, false: int):
        '''Create a predicate node.'''
        self.bb = bb
        self.true = true
        self.false = false

    def get_basic_block(self) -> BasicBlock:
        return self.bb

    def get_true(self) -> int:
        '''Get the true branch destination address.'''
        return self.true

    def get_false(self) -> int:
        '''Get the false branch destination address.'''
        return self.false

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        print(' '*indent + 'if')
        self.bb.print(indent + INDENT)
