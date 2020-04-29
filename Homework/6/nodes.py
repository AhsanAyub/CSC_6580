#!/usr/bin/env python3
#

'''Declare node classes for structuring code.'''


from capstone import CsInsn
from disassembler import InstructionTests
from typing import List, Dict, Set


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

    def __len__(self) -> int:
        '''Get the number of instructions in the basic block.'''
        return len(self.instructions)

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

    def _force_address(self, address: int):
        '''Debugging method.'''
        self.address = address

    def get_next(self) -> int:
        '''Get the next address after this basic block.
        Note: this is not necessarily the next address in the flow!
        '''
        return self.next


class Node(object):
    '''The base class for all nodes.'''

    def __init__(self, address: int):
        '''Make a node with the given address.'''
        self.address = address

    def get_address(self):
        '''Get the address.'''
        return self.address

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.
        Subclasses must implement this.
        '''
        pass

    def get_basic_block(self) -> BasicBlock:
        '''Get the basic block for this node, if any.  If 
        there is none, an empty basic block is returned.
        '''
        return BasicBlock()


class SESENode(Node):
    '''A base class for nodes that have a single entry and a
    single exit.'''
    
    def replace(self, items: Dict[int, "SESENode"], exclude: Set[int] = set()) -> "SESENode":
        '''Replace label references with nodes.  The optional second
        argument specifies addresses that should not be replaced.  This
        is used to prevent infinite regress.
        '''
        return self

    def get_references(self) -> Set[int]:
        '''Get all label references contained in this node.'''
        return set()


class LabelNode(SESENode):
    '''A node that holds an assignment to the label and nothing
    else.
    '''

    # Keep track of reference counts for each address.
    refcount: Dict[int, int] = {}

    # Did anything change?
    dirty: bool = False

    @classmethod
    def get_count(cls, address: int) -> int:
        '''Get the reference count for a given address.'''
        return cls.refcount.get(address,0)

    @classmethod
    def get_singles(cls) -> List[int]:
        '''Get all addresses that have exactly one reference.'''
        return [addr for addr,count in cls.refcount.items() if count == 1]

    @classmethod
    def is_dirty(cls) -> bool:
        return cls.dirty

    @classmethod
    def reset(cls):
        cls.dirty = False

    def __init__(self, address: int):
        '''Make a node setting the label to the given address.'''
        super().__init__(address)
        LabelNode.refcount[address] = LabelNode.refcount.get(address,0) + 1
    
    def __fini__(self):
        LabelNode.refcount[self.get_address()] -= 1

    def __str__(self) -> str:
        '''Generate a string representation.'''
        return LABELVAR + ' := ' + hex(self.address)

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        print(' '*indent + f'{LABELVAR} := {hex(self.address)} ({LabelNode.get_count(self.address)})')

    def get_references(self) -> Set[int]:
        '''Get all label references contained in this node.'''
        return set([self.get_address()])
    
    def replace(self, items: Dict[int, SESENode], exclude: Set[int] = set()) -> SESENode:
        '''Replace label references with nodes.  The optional second
        argument specifies addresses that should not be replaced.  This
        is used to prevent infinite regress.
        '''
        if self.get_address() in exclude:
            return self
        result = items.get(self.get_address(), self)
        if result != self:
            LabelNode.dirty = True
        return result


class FunctionNode(SESENode):
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
        super().__init__(bb.get_address())

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
        super().__init__(bb.get_address())

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


class Sequence(SESENode):
    '''A sequence is a prime that contains a sequence of
    other primes.  Nested sequences are flattened.
    '''

    def __init__(self, parts: List[SESENode]):
        '''Initialize the sequence.'''
        if len(parts) > 0:
            super().__init__(parts[0].get_address())
        else:
            super().__init__(0)
        self.parts: List[SESENode] = []
        for part in parts:
            if isinstance(part, Sequence):
                for subpart in part.get_parts():
                    self.parts.append(subpart)
            else:
                self.parts.append(part)
    
    def get_parts(self) -> List[SESENode]:
        '''Get the parts that make up this sequence.'''
        return self.parts

    def __len__(self) -> int:
        return len(self.parts)

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        for part in self.parts:
            part.print(indent)
    
    def get_references(self) -> Set[int]:
        '''Get all label references contained in this node.'''
        # This should really be a fold, but let's not get carried away.
        refs = set()
        for part in self.parts:
            refs.update(part.get_references())
        return refs
    
    def replace(self, items: Dict[int, SESENode], exclude: Set[int] = set()) -> SESENode:
        '''Replace label references with nodes.  The optional second
        argument specifies addresses that should not be replaced.  This
        is used to prevent infinite regress.
        '''
        exclude = exclude.union([self.get_address()])
        newparts = [part.replace(items, exclude) for part in self.get_parts()]
        return Sequence(newparts)


class IfThenElse(SESENode):
    '''An if-then-else is a prime that contains a predicate
    node and two other primes as the then-part and else-part.
    '''

    def __init__(self, pred: PredicateNode,
            then_part: SESENode, else_part: SESENode):
        '''Initialize the if-then-else.'''
        super().__init__(pred.get_address())
        self.pred = pred
        self.then_part = then_part
        self.else_part = else_part

    def get_pred(self) -> PredicateNode:
        return self.pred

    def get_then_part(self) -> SESENode:
        return self.then_part

    def get_else_part(self) -> SESENode:
        return self.else_part

    def print(self, indent: int = 0):
        '''Print this node at the given indentation level.'''
        self.pred.print(indent)
        print(' '*indent + 'then')
        self.then_part.print(indent + INDENT)
        print(' '*indent + 'else')
        self.else_part.print(indent + INDENT)
        print(' '*indent + 'fi')
    
    def get_references(self) -> Set[int]:
        '''Get all label references contained in this node.'''
        refs = self.then_part.get_references()
        refs.update(self.else_part.get_references())        
        return refs
    
    def replace(self, items: Dict[int, SESENode], exclude: Set[int] = set()) -> SESENode:
        '''Replace label references with nodes.  The optional second
        argument specifies addresses that should not be replaced.  This
        is used to prevent infinite regress.
        '''
        exclude = exclude.union([self.get_address()])
        new_then = self.get_then_part().replace(items, exclude)
        new_else = self.get_else_part().replace(items, exclude)
        return IfThenElse(self.get_pred(), new_then, new_else)
