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
    else.'''
    def __init__(self, address: int):
        '''Make a node setting the label to the given address.'''
        self.address = address
        self.__node_type = "label"

    def __str__(self) -> str:
        '''Generate a string representation.'''
        return LABELVAR + ' := ' + hex(self.address)

    def get_value(self) -> int:
        '''Get the value of the label.'''
        return self.address

    def get_node_type(self) -> str:
        ''' Return the string as identification '''
        return self.__node_type

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
        # To identify the class
        self.__node_type = "function"
        # "Label is the appropirate next value"
        self.__label = next
        # Count the number of times it has been references
        # Defult value is one because it will at least be added in the basic block
        self.__label_count = 1

    def get_basic_block(self) -> BasicBlock:
        return self.bb

    def get_next(self) -> int:
        '''Get the next address in the flow.'''
        return self.next

    def get_node_type(self) -> str:
        ''' Return the string as identification '''
        return self.__node_type

    def set_label(self, address: int):
        ''' Set the starting address of the block to its label '''
        self.__label = address

    def get_label(self) -> int:
        ''' Returh the label '''
        return self.__label

    def increment_label_count(self):
        ''' Add the label count by 1 '''
        self.__label_count += 1

    def get_label_count(self) -> int:
        ''' Return the number of times the label has been referred '''
        return self.__label_count;

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        self.bb.print(indent + INDENT)


class PredicateNode(Node):
    '''A predicate node has a single entry and two exits.

    Essentially a predicate node holds a basic block with
    no branching or loops, except for a conditional branch
    at the final instruction.'''

    def __init__(self, bb: BasicBlock, true: int, false: int):
        '''Create a predicate node.'''
        self.bb = bb
        self.true = true
        self.false = false
        # To identify the class
        self.__node_type = "predicate"
        # Label would be the starting address of the basic block at first
        self.__label = 0
        # Count the number of times it has been references
        # Defult value is one because it will at least be added in the basic block
        self.__label_count = 1

    def get_basic_block(self) -> BasicBlock:
        return self.bb

    def get_true(self) -> int:
        '''Get the true branch destination address.'''
        return self.true

    def get_false(self) -> int:
        '''Get the false branch destination address.'''
        return self.false

    def get_node_type(self) -> str:
        ''' Return the string as identification '''
        return self.__node_type

    def set_label(self, address: int):
        ''' Set the starting address of the block to its label '''
        self.__label = address

    def get_label(self) -> int:
        ''' Returh the label '''
        return self.__label

    def increment_label_count(self):
        ''' Add the label count by 1 '''
        self.__label_count += 1

    def get_label_count(self) -> int:
        ''' Return the number of times the label has been referred '''
        return self.__label_count;

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        #print(' '*indent)
        self.bb.print(indent + INDENT)


class IfThenElseStructure(Node):
    '''This is a custom classes added in this python file that holds
    a basic block ending in true / false branching.'''

    '''Make a if-then-else-fi structure.'''
    def __init__(self, bb: BasicBlock, bb_label: int):
        '''Create a predicate node.'''
        self.bb = bb
        self.bb_label = bb_label
        self.true_bb = None
        self.true_bb_label = None
        self.false_bb = None
        self.false_bb_label = None

    def get_basic_block(self) -> BasicBlock:
        ''' Return the main basic block '''
        return self.bb

    def get_basic_block_label(self) -> int:
        ''' Return the label of the main basic block '''
        return self.bb_label

    def set_true_basic_block(self, true_bb: BasicBlock, true_bb_label: int):
        ''' Initialize the basic block for true condition'''
        self.true_bb = true_bb
        self.true_bb_label = true_bb_label

    def get_true_basic_block(self) -> BasicBlock:
        ''' Return the basic block for true condition'''
        return self.true_bb

    def get_true_basic_block_label(self) -> int:
        ''' Return the label of the basic block for true condition'''
        return self.true_bb_label

    def set_false_basic_block(self, false_bb: BasicBlock, false_bb_label: int):
        ''' Initialize the basic block for false condition'''
        self.false_bb = false_bb
        self.false_bb_label = false_bb_label

    def get_false_basic_block(self) -> BasicBlock:
        ''' Return the basic block for false condition'''
        return self.false_bb

    def get_false_basic_block_label(self) -> int:
        ''' Return the label of the basic block for false condition'''
        return self.false_bb_label

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        # Print self basic block frist
        print("if")
        self.bb.print(indent + INDENT)
        print("then")
        if(self.true_bb != None):
            # Print the basic block for true statement
            self.true_bb.print(indent + INDENT)
            print("\tL = %s" % str(hex(self.true_bb_label)))
        else:
            # Destination is unknown
            print("\texit")
        print("else")
        if(self.false_bb != None):
            # Print the basic block for true statement
            self.false_bb.print(indent + INDENT)
            print("\tL = %s" % str(hex(self.false_bb_label)))
        else:
            # Destination is unknown
            print("\texit")
        print("fi")
        print()


class SequentialBlock(Node):
    '''This is a custom classes added in this python file that holds
    a series of (sequential) basic blocks.'''

    '''Make a sequential block structure.'''
    def __init__(self, bb: BasicBlock, bb_label: int):
        self.bb = bb
        self.bb_label = bb_label

    def get_basic_block(self) -> BasicBlock:
        ''' Return the main basic block '''
        return self.bb

    def get_basic_block_label(self) -> int:
        ''' Return the label for main basic block '''
        return self.bb_label

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        self.bb.print(indent + INDENT)
