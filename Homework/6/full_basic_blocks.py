#!/usr/bin/env python3
#

'''Find and print basic blocks in an executable.
This program reads an ELF file and identifies basic blocks in the .text
section, starting from the entry point (by default) or from a provided
list of basic block leaders.
This module checks the DEBUG environment variable for a comma-separated
list of options.  Do not include whitespace in the DEBUG value.
  * address ........ Print the address of each line of disassembly
  * call-end ....... Treat calls as ending the basic block
  * fancy .......... Use specialized code to print operands
  * group .......... Print the group membership of instructions
  * note ........... Print more information
  * debug .......... Print debugging information
  * rip ............ Resolve RIP-relative addresses and print
  * syscall-end .... Treat syscalls as ending the basic block
'''

from sys import argv, stderr
from os import environ
## CS_ARCH_X86: the X86 ISA (Capstone supports several)
## CS_MODE_32: the 32 bit mode
## CS_MODE_64: the 64 bit mode
## Cs: the Capstone disassembler interface
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsInsn
## X86_REG_RIP: the integer value used in Capstone for RIP
from capstone.x86 import X86_REG_RIP
## X86_OP_MEM: memory operand (inc [rbx+rcx*8-8])
## X86_OP_REG: register operand (inc rcx)
## X86_OP_IMM: immediate operand (jmp 0x00000000000021e4)
## X86_GRP_JUMP: jump (1)
## X86_GRP_CALL: call (2)
## X86_GRP_RET: return (3)
## X86_GRP_INT: interrupt (4)
## X86_GRP_IRET: return from interrupt (5)
## X86_GRP_PRIVILEGE: privilege (6)
## X86_GRP_BRANCH_RELATIVE: relative branch (7)
## Note the parentheses so that the instruction can extend over multiple
## lines!
from capstone.x86_const import (X86_OP_MEM, X86_OP_REG, X86_OP_IMM,
    X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET, X86_GRP_INT,
    X86_GRP_IRET, X86_GRP_PRIVILEGE, X86_GRP_BRANCH_RELATIVE)
from elftools.elf.elffile import ELFFile, Section
from elftools.elf.constants import SH_FLAGS
from typing import List

# Check for debugging information.
if 'DEBUG' in environ:
    ## Split on commas, if any.  The result is a list of the strings.
    DEBUG = environ['DEBUG'].split(',')
else:
    ## DEBUG wasn't set in the environment, so use an empty list of
    ## options.
    DEBUG = []

# See if debugging is enabled?
DEBUGGING = 'debug' in DEBUG
if DEBUGGING:
    def debug(msg):
        print(f"DEBUG: {msg}", flush=True)
    debug("debugging enabled")
else:
    def debug(msg):
        pass

# Determine whether or not a call instruction ends a basic block.
CALL_ENDS_BB = 'call-end' in DEBUG
if CALL_ENDS_BB:
    debug("calls end basic blocks")

# Determine whether an interrupt ends a basic block.
SYSCALL_ENDS_BB = 'syscall-end' in DEBUG
if SYSCALL_ENDS_BB:
    debug("syscalls end basic blocks")

# Print notes or don't print notes.
PRINT_NOTES = 'note' in DEBUG
if PRINT_NOTES:
    debug("printing notes")

# Print addresses for each line of disassembly?
PRINT_ADDRESSES = 'address' in DEBUG
if PRINT_ADDRESSES:
    debug("printing addresses")

# Print instruction groups?
PRINT_GROUPS = 'group' in DEBUG
if PRINT_GROUPS:
    debug("printing instruction groups")

# Solve and print RIP-relative addresses?
PRINT_RIP = 'rip' in DEBUG
if PRINT_RIP:
    debug("computing RIP-relative addresses")

# See if we should print fancy operands?
FANCY_OPERANDS = 'fancy' in DEBUG
if FANCY_OPERANDS:
    debug("using fancy operand printing")

# Convert from ELF tools to constants used by Capstone.
decoder_ring = {
    'EM_386': CS_ARCH_X86,
    'EM_X86_64': CS_ARCH_X86,
    'ELFCLASS32': CS_MODE_32,
    'ELFCLASS64': CS_MODE_64
}

def is_mem(oper):
    '''Provided with an operand, determine if it is a memory reference.'''
    return oper.type == X86_OP_MEM

def is_imm(oper):
    '''Provided with an operand, determine if it is immediate.'''
    return oper.type == X86_OP_IMM

def is_reg(oper):
    '''Provided with an operand, determine if it is a register.'''
    return oper.type == X86_OP_REG

def is_rip_relative(oper):
    '''Determine if an operand is RIP-relative.  If so, return the offset.
    If not, return None.'''
    if oper.type == X86_OP_MEM and oper.value.mem.base == X86_REG_RIP:
        # Get the displacement.
        return oper.value.mem.disp
    return None


class AddressException(Exception):
    '''Address is out of bounds.'''
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return f"Address Out Of Bounds: {hex(self.address)}"


class NotExecutableException(Exception):
    '''A referenced section is not executable.'''
    def __init__(self, section: Section):
        self.section: Section = section

    def __str__(self):
        return f'Section is not executable: {self.section.name}: {self.section.header}'


class SectionFinder(object):
    '''This little class stores sections and lets us look up a section by a given
    virtual address.  Because the use case is going to (often) be that the section
    searched is the same as the previous section searched (because instructions
    tend to be section-local) we keep track of the last section returned.  If the
    address is not in that section, we go looking.  This is sped up by keeping the
    section list ordered by incresing address.  Note that if sections overlap this
    can cause returned results to be inconsistent.
    To use this, make an instance and then `add` sections to it.  To find a section
    for a given virutal address, call `find` with the address.  If None is returned,
    then there is no section correspoding to that address.  No overlap checking is
    performed.'''

    def __init__(self):
        '''Initialize the class with an empty collection of sections.'''
        self._sections: List(Section) = []
        self._last_section: Section = None
        self._last_start = 0
        self._last_end = 0

    @classmethod
    def contains(cls, section: Section, address: int) -> bool:
        '''Determine if the given section contains the given address.'''
        base = section.header.sh_addr
        length = section.data_size
        return base <= address and address < base + length

    def add(self, section: Section):
        '''Add a section to the list of sections.'''
        # The section just added becomes the first section searched.
        self._last_section = section
        self._last_start = section.header.sh_addr
        self._last_end = section.data_size + self._last_start

        # Insertion sort the new section into the list by increasing address.
        index = len(self._sections)
        while index > 0 and self._sections[index-1].header.sh_addr < section.header.sh_addr:
            index -= 1
        self._sections.insert(index, self._last_section)

    def find(self, address: int) -> Section:
        '''Find and return a section that contains a given address.'''
        if self._last_start <= address and address < self._last_end:
            return self._last_section
        for section in self._sections:
            if SectionFinder.contains(section, address):
                self._last_section = section
                self._last_start = section.header.sh_addr
                self._last_end = section.data_size + self._last_start
                return section
        return None


class RAD:
    '''Provide a random access disassembler (RAD).'''
    def __init__(self, sections: SectionFinder, arch, bits):
        '''Start disassembly of the provided code blob.
        Arguments:
            sections -- A section finder instance.
            arch -- The architecture, as defined by Capstone.
            bits -- The bit width, as defined by Capstone.
        '''
        # Set up options for disassembly.
        self.md = Cs(arch, bits)
        self.md.skipdata = True
        self.md.detail = True
        self.sections = sections
        self._last_data = None
        self._last_start = 0
        self._last_end = 0

    def at(self, address):
        '''Try to disassemble and return the instruction starting at
        the given address.  An AddressException is thrown if the address
        is not present in any of the sections, and a NotExecutableException
        is thrown if the address is in a section that is not executable.
        '''
        if address >= self._last_end or address < self._last_start:
            # We need to find the section and initialize all variables.
            # Find a section that contains the address.
            section = self.sections.find(address)
            if section is None:
                # No section contains the address.
                raise AddressException(address)

            # Make sure the section is executable and allocated.
            flags = section.header.sh_flags
            if (flags & SH_FLAGS.SHF_ALLOC) * (flags & SH_FLAGS.SHF_EXECINSTR) == 0:
                # This section is not allocated or does not contain code.
                raise NotExecutableException(section)

            # Set the variables so we skip this next time.
            self._last_data = section.data()
            self._last_start = section.header.sh_addr
            self._last_end = self._last_start + section.data_size

        # Compute the index into the section's data for the given address.  We
        # already know the address is in the given section (we checked earlier).
        index = address - self._last_start

        # The maximun length of an x86-64 instruction is 15 bytes.  You can
        # exceed this with prefix bytes and the like, but you will get an
        # "general protection" (GP) exception on the processor.  So don't do
        # that.
        return next(self.md.disasm(self._last_data[index:index+15], address, count=1))

    def in_range(self, address):
        '''Determine if an address is in range and executable.'''
        section = self.sections.find(address)
        flags = section.header.sh_flags
        return (section is not None and (flags & SH_FLAGS.SHF_ALLOC)
                and (flags & SH_FLAGS.SHF_EXECINSTR))


def print_disassembly(address: int, inst: CsInsn):
    '''Print a line of disassembly honoring all the various debugging
    settings.'''
    grp = ""
    addr = ""
    rel = ""
    fancy = None
    if PRINT_GROUPS:
        grp = f"; Groups: {list(map(inst.group_name, inst.groups))}"
        grp = f"{grp:30}"
    if PRINT_ADDRESSES:
        addr = f"{hex(address):>18}  "
    if PRINT_RIP:
        for operand in inst.operands:
            disp = is_rip_relative(operand)
            if disp is not None:
                rel += f"{hex(disp + inst.size + address)} "
        if len(rel) > 0:
            rel = f"; RIP-Refs: {rel:12}"
    if FANCY_OPERANDS:
        # This is overkill, of course.  It just lets me mess with
        # the operands in case I want to do something special, and
        # (I hope) demonstrates how you can pull apart the operands
        # to an instruction.
        fancy = []
        for operand in inst.operands:
            if operand.type == X86_OP_IMM:
                fancy.append(f"{hex(operand.value.imm)}")
            elif operand.type == X86_OP_REG:
                fancy.append(f"{inst.reg_name(operand.value.reg)}")
            elif operand.type == X86_OP_MEM:
                segment = inst.reg_name(operand.value.mem.segment)
                base = inst.reg_name(operand.value.mem.base)
                index = inst.reg_name(operand.value.mem.index)
                scale = str(operand.value.mem.scale)
                disp = operand.value.mem.disp
                value = f"[{base}"
                if index is not None:
                    value += f" + {index}*{scale}"
                if disp > 0:
                    value += f" + {hex(disp)}"
                elif disp < 0:
                    value += f" - {hex(abs(disp))}"
                if segment is not None:
                    value = f"{segment}:" + value
                value += "]"
                fancy.append(value)
            else:
                fancy.append("???")
        line = f"{inst.mnemonic:10} {', '.join(fancy)}"
    else:
        line = f"{inst.mnemonic:5} {inst.op_str:30}"
    print(f"  {addr}{line:40}{grp}{rel}")


def error(msg):
    '''Print an error message.  The message is sent to standard error.'''
    print(f"ERROR: {msg}", file=stderr, flush=True)


def note(msg):
    '''Print a note to standard output.  The stream is flushed to synchonize.'''
    if PRINT_NOTES:
        print(f"Note: {msg}", flush=True)


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


def find_and_print(filename, explore=[]):
    '''Disassemble the specified file and identify basic blocks, tracing potential
    execution flow.  Addresses of an initial set of addresses to explore can be provided.
    If this set is empty, then the entry point of the ELF file is used.'''
    with open(filename, "rb") as f:
        print(f"{filename}")
        # Try to decode as ELF.
        try:
            elf = ELFFile(f)
        except:
            error("Could not parse the file as ELF; cannot continue.")
            exit(1)

        # Convert and check to see if we support the file.
        bits = decoder_ring.get(elf['e_ident']['EI_CLASS'], None)
        arch = decoder_ring.get(elf['e_machine'], None)
        debug(f"arch: {arch}, bits: {bits}")
        if arch is None:
            error(f"Unsupported architecture {elf['e_machine']}")
            exit(1)
        if bits is None:
            error(f"Unsupported bit width {elf['e_ident']['EI_CLASS']}")
            exit(1)

        # Put all sections into a section finder, then build a random access
        # disassembler.
        sections = SectionFinder()
        for section in elf.iter_sections():
            debug(f"adding section {section.name}")
            sections.add(section)
        rad = RAD(sections, arch, bits)

        # Get the entry point from the ELF header, and then get the section that
        # contains the entry point.
        entry = elf.header.e_entry

        # If no leaders were given, then add then entry point as a leader.  Otherwise
        # we have nothing to do!
        if len(explore) == 0:
            explore = [entry]

        # Do both passes.
        bbs = do_pass_one(explore, rad)
        do_pass_two(bbs, rad)

    print()


def do_pass_one(explore, rad):
    '''Find basic block leaders in a program.  This returns a list of the
    leaders (addresses).  A list of initial leaders must be provided as the
    first argument, and an initialized random access disassembler as the
    second.'''

    note("Starting pass one")

    # We maintain a stack of addresses to explore (explore).  We also maintain
    # a set of basic block leaders we have discovered (bbs).
    bbs = set(explore)
    def add_explore(addr):
        '''Add an address to be explored, if it is not already scheduled to
        be explored.'''
        if addr not in explore:
            explore.append(addr)
    def add_leader(addr):
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
        if i.group(X86_GRP_CALL):
            debug(f"found call at {hex(i.address)}; target is a leader")
            # This is a call.  Push the call target and the next
            # address on the stack to explore.  The call target is
            # a basic block leader.  If calls end the basic block, then
            # the next address after the call is also a leader.  We
            # assume all calls return.
            if is_imm(i.operands[0]):
                add_leader(i.operands[0].value.imm)
            elif is_mem(i.operands[0]):
                # We can only handle RIP-based addressing.
                disp = is_rip_relative(i.operands[0])
                if disp is not None:
                    # Now we can compute the address of the call.
                    add_leader(nextaddr+disp)
            if CALL_ENDS_BB:
                add_leader(nextaddr)
            else:
                add_explore(nextaddr)

        elif i.group(X86_GRP_BRANCH_RELATIVE) or i.group(X86_GRP_JUMP):
            if i.mnemonic == 'jmp':
                debug(f"found jump at {hex(i.address)}; target is leader")
                # This is a jump.  Note that you need to test for this after
                # relative branch because those are also in the jump group.
                if is_imm(i.operands[0]):
                    # The target of the jump is the leader of a basic block.
                    add_leader(i.operands[0].value.imm)
                elif is_mem(i.operands[0]):
                    # We can only handle RIP-based addressing.
                    disp = is_rip_relative(i.operands[0])
                    if disp is not None:
                        # Now we compute the address of the jump.
                        add_leader(nextaddr+disp)
            else:
                debug(f"found branch at {hex(i.address)}; true and false branches are leaders")
                # This is a conditional branch.  Both the target of the branch
                # and the instruction following the branch are leaders.
                add_leader(i.operands[0].value.imm)
                add_leader(nextaddr)

        elif i.group(X86_GRP_INT):
            debug(f"found interrupt at {hex(i.address)}; possible leader")
            # This is an interrupt.  Assume we return and continue.
            if SYSCALL_ENDS_BB:
                add_leader(nextaddr)
            else:
                add_explore(nextaddr)

        elif i.mnemonic == 'hlt' or i.group(X86_GRP_RET) or i.group(X86_GRP_IRET):
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


def do_pass_two(bbs, rad):
    '''Run pass two of basic block discovery.  This prints the disassembly
    of all basic blocks, given the set of basic block leaders as the first
    argument and an initialized random access disassembler as the second.'''

    note("Starting pass two")

    # Now print the basic blocks.  We want to print them in order by address,
    # so let's sort the set.
    sort_bbs = list(bbs)
    sort_bbs.sort()
    count = 0
    for address in sort_bbs:
        debug(f"Possible basic block at {hex(address)}")
        if not rad.in_range(address):
            continue

        # Print the basic block starting at this location.
        count += 1
        print(f"\nblock at: {hex(address)}")
        while address != None:
            # Disassemble the instruction.
            try:
                i = rad.at(address)
            except AddressException:
                # Ignore and let the basic block be terminated.
                address = None
                continue
            except NotExecutableException:
                # Ignore and let the basic block be terminated.
                address = None
                continue

            # Compute the next address and the disassembled instruction.
            nextaddr = i.address + i.size
            print_disassembly(address, i)

            # Determine if there is a next address for us to disassemble in this
            # basic block.
            address = None
            if i.group(X86_GRP_CALL):
                if CALL_ENDS_BB:
                    # The call ends the basic block.
                    print(f"next: {hex(nextaddr)}")
                else:
                    # Assume the call returns and disassemble the next address as part
                    # of this basic block.
                    address = nextaddr

            elif i.group(X86_GRP_BRANCH_RELATIVE) or i.group(X86_GRP_JUMP):
                # A branch or jump ends the basic block.
                if i.mnemonic == 'jmp':
                    if is_imm(i.operands[0]):
                        print(f"next: {i.op_str}")
                    elif is_mem(i.operands[0]):
                        disp = is_rip_relative(i.operands[0])
                        if disp is not None:
                            print(f"next: {hex(nextaddr + disp)}")
                        else:
                            print("next: unknown")
                    else:
                        print("next: unknown")
                else:
                    print(f"true: {i.op_str}")
                    print(f"false: {hex(nextaddr)}")

            elif i.group(X86_GRP_INT):
                if SYSCALL_ENDS_BB:
                    # The system call ends the basic block.
                    print(f"next: {hex(nextaddr)}")
                else:
                    # Assume the system call returns and disassemble the next address
                    # as part of this basic block.
                    address = nextaddr

            elif i.mnemonic == 'hlt' or i.group(X86_GRP_IRET) or i.group(X86_GRP_RET):
                # A halt or return ends the basic block.
                print("next: unknown")

            else:
                # The basic block continues.
                address = nextaddr

            # If the address is in the set of basic block starts, terminate
            # this basic block.
            if address in bbs:
                print(f"next: {hex(address)}")
                address = None
                continue

    note("Finished pass two")
    note(f"Wrote {count} basic blocks")


if __name__ == "__main__":
    main()
