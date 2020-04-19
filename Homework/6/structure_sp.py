#!/usr/bin/env python3
#

'''Generate structured code from the basic blocks of a program.

This program reads an ELF file and identifies basic blocks in the .text
section, starting from the entry point (by default) or from a provided
list of basic block leaders.

If the entry point is used, then a simple heuristic is used to identify
the main function of the program (assuming that the program was compiled
with the C runtime).
'''

from sys import argv
from debug import error, note, debug, DebugOpts
from disassembler import (RAD, AddressException, NotExecutableException,
    DisassemblerException, OperandTests, InstructionTests, CsInsn)
from nodes import FunctionNode, PredicateNode, BasicBlock, Node
from typing import List, Set, Union, Dict


def main():
    '''Disassemble the file given on the command line and identify basic blocks.
    Add any leaders specified on the command line after the file name, which is
    required.  If no leaders are specified, use the entry point.'''
    if len(argv) < 2:
        error("File name is required.")
        exit(1)
    debug(f"Command line arguments: {argv}")
    filename = argv[1]
    leaders = list(map(lambda x: int(x,0), argv[2:]))
    find_and_print(filename, leaders)
    exit(0)


def find_main(rad: RAD, instructions: List[CsInsn]) -> Union[None,int]:
    '''Try to find main by interpreting the given basic block as starting the
    C runtime.'''

    # Bail if there aren't at least two instructions.
    if len(instructions) < 2:
        note("Entry point too short to be C stub.")
        return None

    # Check that the last thing is a call.
    last = instructions[-1]
    if last.mnemonic == 'hlt':
        last = instructions[-2]
    if last.mnemonic != 'call':
        # Last thing in the block must be a call.
        note("Last effective instruction in block is not a call.")
        return None

    # Found a call.  It should be RIP relative and out of scope.
    address = OperandTests.is_rip_relative(last.operands[0])
    if address is not None and rad.in_range(address):
        # The C runtime would be out of range.
        note("Last effective instruction in block is call in range.")
        return None

    # Run through this and find a setting for RDI.
    main_addr = None
    for insn in instructions:
        # See if this is a mov.
        if insn.mnemonic != 'mov' and insn.mnemonic != 'lea':
            continue

        # See if the first operand is the RDI register.
        dest = insn.operands[0]
        sour = insn.operands[1]
        if not OperandTests.is_reg(dest) or insn.reg_name(dest.reg) != 'rdi':
            continue

        # Find out what value is being set for RDI.
        if insn.mnemonic == 'mov' and OperandTests.is_imm(sour):
            main_addr = sour.value.imm
        elif insn.mnemonic == 'lea':
            main_addr = OperandTests.is_rip_relative(sour)
            main_addr += insn.address + insn.size

    # Either we found main or we didn't.
    if main_addr is not None:
        note("Possible main function at " + hex(main_addr))
    return main_addr


def find_and_print(filename: str, explore: List[int] = []):
    '''Disassemble the specified file and identify basic blocks, tracing potential
    execution flow.  Addresses of an initial set of addresses to explore can be provided.
    If this set is empty, then the entry point of the ELF file is used.'''
    with open(filename, "rb") as f:
        print(f"{filename}")
        rad = RAD.build_disassembler(f)

        # Get the entry point from the ELF header, and then get the section that
        # contains the entry point.
        entry = rad.get_entry_point()

        # If no leaders were given, then add then entry point as a leader.  Otherwise
        # we have nothing to do!
        if len(explore) == 0:
            explore = [entry]

        # Do both passes.
        bbs = do_pass_one(explore, rad)
        nodes = do_pass_two(bbs, rad)

        # Check to see if we got exactly one node and, if we did, whether this is
        # starting the C runtime.
        if len(nodes) == 1:
            # We found just one node.  Get the basic block and see if this looks like
            # we are starting the C runtime.
            bb = nodes[next(nodes.__iter__())].get_basic_block()
            instructions = bb.get_instructions()
            main_addr = find_main(rad, instructions)
            if main_addr is not None:
                # Reprocess with the new address.
                explore = [main_addr]
                bbs = do_pass_one(explore, rad)
                nodes = do_pass_two(bbs, rad)

        # Print nodes.
        for address in nodes:
            nodes[address].print(0)
            print()

    print()


def do_pass_one(explore: List[int], rad: RAD) -> Set[int]:
    '''Find basic block leaders in a program.  This returns a list of the
    leaders (addresses).  A list of initial leaders must be provided as the
    first argument, and an initialized random access disassembler as the
    second.'''

    note("Starting pass one")

    # We maintain a stack of addresses to explore (explore).  We also maintain
    # a set of basic block leaders we have discovered (bbs).
    bbs = set(explore)
    def add_explore(addr: int):
        '''Add an address to be explored, if it is not already scheduled to
        be explored.'''
        if addr not in explore:
            explore.append(addr)
    def add_leader(addr: int):
        '''Add a leader to the set of leaders, and also to the set of addresses
        to be explored.'''
        debug(f"adding leader: {hex(addr)}")
        if addr not in bbs:
            bbs.add(addr)
            add_explore(addr)

    # Disassemble the file, follow the links, and build a list of basic blocks
    # leaders.  Within this loop the explore list is treated as an (initialized)
    # stack to perform instruction tracing, and does not always contain only basic
    # block leaders.  Ultimately we have to discover the rest of the leaders we
    # can find, and those go in the bbs set.  Once the explore stack is empty,
    # we have finished, and bbs will contain all the potential basic block
    # leaders we have discovered.
    while len(explore) > 0:
        # Get the next address from the stack.
        address = explore.pop()

        # Disassemble at the address.
        try:
            i = rad.at(address)
        except AddressException:
            # This address is out of range; ignore and continue.
            continue
        except NotExecutableException:
            # This address is not executable; ignore and continue.
            continue

        # Figure out the address that is one byte past the end of the
        # current instruction.  This is likely the address of the next
        # instruction in sequence.
        nextaddr = i.address + i.size

        # Based on the instruction type, determine the next address(es).
        # There are three things we can do here.
        #   (1) Add an address to the set of leaders (and the explore stack)
        #   (2) Add an address to the explore stack (it is not a leader)
        #   (3) Do nothing
        if InstructionTests.is_call(i):
            debug(f"found call at {hex(i.address)}; target is a leader")
            # This is a call.  Push the call target and the next
            # address on the stack to explore.  The call target is
            # a basic block leader.  If calls end the basic block, then
            # the next address after the call is also a leader.  We
            # assume all calls return.
            if OperandTests.is_imm(i.operands[0]):
                add_leader(i.operands[0].value.imm)
            elif OperandTests.is_mem(i.operands[0]):
                # We can only handle RIP-based addressing.
                disp = OperandTests.is_rip_relative(i.operands[0])
                if disp is not None:
                    # Now we can compute the address of the call.
                    add_leader(nextaddr+disp)
            if DebugOpts.CALL_ENDS_BB:
                add_leader(nextaddr)
            else:
                add_explore(nextaddr)

        elif InstructionTests.is_branch(i) or InstructionTests.is_jump(i):
            if i.mnemonic == 'jmp':
                debug(f"found jump at {hex(i.address)}; target is leader")
                # This is a jump.  Note that you need to test for this after
                # relative branch because those are also in the jump group.
                if OperandTests.is_imm(i.operands[0]):
                    # The target of the jump is the leader of a basic block.
                    add_leader(i.operands[0].value.imm)
                elif OperandTests.is_mem(i.operands[0]):
                    # We can only handle RIP-based addressing.
                    disp = OperandTests.is_rip_relative(i.operands[0])
                    if disp is not None:
                        # Now we compute the address of the jump.
                        add_leader(nextaddr+disp)
            else:
                debug(f"found branch at {hex(i.address)}; true and false branches are leaders")
                # This is a conditional branch.  Both the target of the branch
                # and the instruction following the branch are leaders.
                add_leader(i.operands[0].value.imm)
                add_leader(nextaddr)

        elif InstructionTests.is_interrupt(i):
            debug(f"found interrupt at {hex(i.address)}; possible leader")
            # This is an interrupt.  Assume we return and continue.
            if DebugOpts.SYSCALL_ENDS_BB:
                add_leader(nextaddr)
            else:
                add_explore(nextaddr)

        elif (i.mnemonic == 'hlt' or InstructionTests.is_ret(i) or
            InstructionTests.is_interrupt_return(i)):
            debug(f"found halt or return at {hex(i.address)}")
            # These end the basic block and flow does not continue to
            # the next instruction, so do not add anything to explore.
            pass

        else:
            # Assume this instruction flows to the next instruction
            # in sequence, but that instruction is not necessarily
            # a leader.
            add_explore(nextaddr)

    note("Pass one complete")
    note(f"Discovered {len(bbs)} potential basic blocks")

    return bbs


def do_pass_two(bbs: Set[int], rad: RAD) -> Dict[int, Node]:
    '''Run pass two of basic block discovery.
    
    This builds the basic blocks, creates function and predicate nodes from them,
    and stores these in a dictionary by their first address.'''

    note("Starting pass two")

    # Dictionary to hold nodes.
    nodes: Dict[int, Node] = {}

    # Now generate the nodes.
    count = 0
    for address in bbs:
        debug(f"Possible basic block at {hex(address)}")
        if not rad.in_range(address):
            continue

        # Create a basic block starting at this location.
        bb = BasicBlock()
        node: Node
        count += 1
        run = True
        while run:
            # Disassemble the instruction.
            try:
                i = rad.at(address)
            except AddressException:
                # Ignore and let the basic block be terminated.
                run = False
                continue
            except NotExecutableException:
                # Ignore and let the basic block be terminated.
                run = False
                continue

            # Add the instruction to the basic block.
            nextaddr = i.address + i.size
            bb.add(i)

            # Determine if there is a next address for us to disassemble in this
            # basic block.
            run = False
            if InstructionTests.is_call(i):
                if DebugOpts.CALL_ENDS_BB:
                    # The call ends the basic block.
                    node = FunctionNode(bb, nextaddr)
                    nodes[bb.get_address()] = node
                    continue
                else:
                    # Assume the call returns and disassemble the next address as part
                    # of this basic block.
                    address = nextaddr
                    run = True

            elif InstructionTests.is_branch(i) or InstructionTests.is_jump(i):
                # A branch or jump ends the basic block.
                if InstructionTests.is_jump(i) and not InstructionTests.is_branch(i):
                    if OperandTests.is_imm(i.operands[0]):
                        node = FunctionNode(bb, int(i.op_str,0))
                        nodes[bb.get_address()] = node
                    elif OperandTests.is_mem(i.operands[0]):
                        disp = OperandTests.is_rip_relative(i.operands[0])
                        if disp is not None:
                            node = FunctionNode(bb, nextaddr + disp)
                            nodes[bb.get_address()] = node
                        else:
                            node = FunctionNode(bb, 0)
                            nodes[bb.get_address()] = node
                    else:
                        node = FunctionNode(bb, 0)
                        nodes[bb.get_address()] = node
                else:
                    node = PredicateNode(bb, int(i.op_str,0), nextaddr)
                    nodes[bb.get_address()] = node
                continue

            elif InstructionTests.is_interrupt(i):
                if DebugOpts.SYSCALL_ENDS_BB:
                    # The system call ends the basic block.
                    node = FunctionNode(bb, nextaddr)
                    nodes[bb.get_address()] = node
                    continue
                else:
                    # Assume the system call returns and disassemble the next address
                    # as part of this basic block.
                    address = nextaddr
                    run = True

            elif (i.mnemonic == 'hlt' or InstructionTests.is_ret(i) or
                InstructionTests.is_interrupt_return(i)):
                # A halt or return ends the basic block.
                node = FunctionNode(bb, 0)
                nodes[bb.get_address()] = node
                continue

            else:
                # The basic block continues.
                address = nextaddr
                run = True

            # If the address is in the set of basic block starts, terminate
            # this basic block.
            if address in bbs:
                node = FunctionNode(bb, address)
                nodes[bb.get_address()] = node
                run = False

    note("Finished pass two")
    note(f"Wrote {count} basic blocks")
    note(f"Generated {len(nodes)} nodes")

    return nodes


if __name__ == "__main__":
    main()
