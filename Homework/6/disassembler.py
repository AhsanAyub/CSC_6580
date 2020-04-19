#!/usr/bin/env python3
#

'''Provide classes to disassemble the content of a file.

Some common tests on instructions and operands are provided by
InstructionTests and OperandTests, respectively.

The primary interface to this module is the RAD class.  To get started
see the static method build_disassembler() in RAD.
'''


# The idea is that this is the only module that needs to know about the
# details of Elf Tools and Capstone.


from elftools.elf.elffile import ELFFile, Section
from elftools.elf.constants import SH_FLAGS
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsInsn
from capstone.x86 import X86_REG_RIP, X86Op
from capstone.x86_const import (X86_OP_MEM, X86_OP_REG, X86_OP_IMM)
from capstone.x86_const import (X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET,
    X86_GRP_INT, X86_GRP_IRET, X86_GRP_PRIVILEGE, X86_GRP_BRANCH_RELATIVE)

from typing import List, Union

from debug import (DebugOpts, error, debug)


class OperandTests:
    '''Provide some common tests on operands.'''

    @staticmethod
    def is_mem(oper: X86Op) -> bool:
        '''Provided with an operand, determine if it is a memory reference.'''
        return oper.type == X86_OP_MEM

    @staticmethod
    def is_imm(oper: X86Op) -> bool:
        '''Provided with an operand, determine if it is immediate.'''
        return oper.type == X86_OP_IMM

    @staticmethod
    def is_reg(oper: X86Op) -> bool:
        '''Provided with an operand, determine if it is a register.'''
        return oper.type == X86_OP_REG

    @staticmethod
    def is_rip_relative(oper: X86Op) -> Union[None, int]:
        '''Determine if an operand is RIP-relative.  If so, return the offset.
        If not, return None.'''
        if oper.type == X86_OP_MEM and oper.value.mem.base == X86_REG_RIP:
            # Get the displacement.
            return oper.value.mem.disp
        return None


class InstructionTests:
    '''Provide some common tests on instructions.'''

    @staticmethod
    def is_jump(insn: CsInsn) -> bool:
        '''Determine if an instruction is an unconditional jump.'''
        return insn.group(X86_GRP_JUMP)

    @staticmethod
    def is_call(insn: CsInsn) -> bool:
        '''Determine if an instruction is a call.'''
        return insn.group(X86_GRP_CALL)

    @staticmethod
    def is_ret(insn: CsInsn) -> bool:
        '''Determine if an instruction is a return.'''
        return insn.group(X86_GRP_RET)

    @staticmethod
    def is_branch(insn: CsInsn) -> bool:
        '''Determine if an instruction is a conditional branch.'''
        return insn.group(X86_GRP_BRANCH_RELATIVE)

    @staticmethod
    def is_interrupt_return(insn: CsInsn) -> bool:
        '''Determine if an instruction is a return from interrupt.'''
        return insn.group(X86_GRP_IRET)

    @staticmethod
    def is_privileged(insn: CsInsn) -> bool:
        '''Determine if an instruciton is privileged.'''
        return insn.group(X86_GRP_PRIVILEGE)

    @staticmethod
    def is_interrupt(insn: CsInsn) -> bool:
        '''Determine if an instruction is an interrupt.'''
        return insn.group(X86_GRP_INT)


class DisassemblerException(Exception):
    '''Disassembly failed.'''
    def __init__(self, msg: str):
        self.msg = msg

    def __str__(self):
        return f"Cannot disassemble: {self.msg}"


class AddressException(Exception):
    '''Address is out of bounds.'''
    def __init__(self, address: int):
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
    def __init__(self, sections: SectionFinder, arch, bits, entry: int):
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
        self._last_data = bytes([])
        self._last_start = 0
        self._last_end = 0
        self._entry = entry

    def get_entry_point(self) -> int:
        '''Get the entry point address.'''
        return self._entry

    def at(self, address: int) -> CsInsn:
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

    def in_range(self, address: int):
        '''Determine if an address is in range and executable.'''
        section = self.sections.find(address)
        if section is None:
            return False
        flags = section.header.sh_flags
        return ((flags & SH_FLAGS.SHF_ALLOC)
                and (flags & SH_FLAGS.SHF_EXECINSTR))

    @staticmethod
    def print_disassembly(address: int, inst: CsInsn):
        '''Print a line of disassembly honoring all the various debugging
        settings.'''
        grp = ""
        addr = ""
        rel = ""
        fancy = None
        if DebugOpts.PRINT_GROUPS:
            grp = f"; Groups: {list(map(inst.group_name, inst.groups))}"
            grp = f"{grp:30}"
        if DebugOpts.PRINT_ADDRESSES:
            addr = f"{hex(address):>18}  "
        if DebugOpts.PRINT_RIP:
            for operand in inst.operands:
                disp = OperandTests.is_rip_relative(operand)
                if disp is not None:
                    rel += f"{hex(disp + inst.size + address)} "
            if len(rel) > 0:
                rel = f"; RIP-Refs: {rel:12}"
        if DebugOpts.FANCY_OPERANDS:
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
                    if disp is not None:
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

    @staticmethod
    def build_disassembler(file) -> "RAD":
        '''Given an open file, attempt to decode it as an ELF file.

        This processes all the sections into a SectionFinder instance,
        and then uses it to construct and return a RAD instance.
        '''
        # Try to decode as ELF.
        try:
            elf = ELFFile(file)
        except:
            raise DisassemblerException("Could not parse the file as ELF; cannot continue.")

        # Convert from ELF tools to constants used by Capstone.
        decoder_ring = {
            'EM_386': CS_ARCH_X86,
            'EM_X86_64': CS_ARCH_X86,
            'ELFCLASS32': CS_MODE_32,
            'ELFCLASS64': CS_MODE_64
        }

        # Convert and check to see if we support the file.
        bits = decoder_ring.get(elf['e_ident']['EI_CLASS'], None)
        arch = decoder_ring.get(elf['e_machine'], None)
        debug(f"arch: {arch}, bits: {bits}")
        if arch is None:
            raise DisassemblerException(f"Unsupported architecture {elf['e_machine']}")
        if bits is None:
            raise DisassemblerException(f"Unsupported bit width {elf['e_ident']['EI_CLASS']}")

        # Put all sections into a section finder, then build a random access
        # disassembler.
        sections = SectionFinder()
        for section in elf.iter_sections():
            debug(f"adding section {section.name}")
            sections.add(section)
        return RAD(sections, arch, bits, elf.header.e_entry)


if __name__ == "__main__":
    print("ERROR: This module is not meant to be run directly.")
