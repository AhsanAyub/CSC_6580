#!/usr/bin/env python3
#

# Importing libraries
import sys
from capstone import *
from elftools.elf.elffile import ELFFile
from rad import *

# Convert from ELF tools to constants used by Capstone.
decoder_ring = {
    'EM_386': CS_ARCH_X86,
    'EM_X86_64': CS_ARCH_X86,
    'ELFCLASS32': CS_MODE_32,
    'ELFCLASS64': CS_MODE_64
}

def error(msg):
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)

def do_pass_two(bbs, rad):
    bbs.sort()
    print(rad.offset)
    print(bbs[0])
    #len = len(bbs)
    flag = 0
    bbs_index = 0
    print("block at: " + str(hex(bbs[1])))
    for i in rad.md.disasm(rad.code, rad.offset):
        #print("\t%s\t%s" %(i.mnemonic, i.op_str))
        if(i.address == bbs[0] or flag == 1):
            flag = 1
            print("\t%s\t%s" %(i.mnemonic, i.op_str))
            '''if(i.address == bbs[1]):
                break
            else:
                continue'''

def do_pass_one(explore, rad):
    # Track whether we have found branches.
    branches = False
    count_branch = 0

    # Iterating through the loop
    for i in rad.md.disasm(rad.code, rad.offset):
        if 1 in i.groups or 7 in i.groups:      # Condition to find branches
            if(len(i.operands) > 0 and is_imm(i.operands[0])):
                current_loc = int(i.op_str, 0)
            else:
                current_loc = -1
            next_loc = i.address + i.size

            # Conditional jump: target and next instruction are leaders
            if(1 in i.groups and 7 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(i.address)):
                    explore.append(current_loc)
                continue

            # call <addr> : target and next instruction are leaders
            if(2 in i.groups and 7 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(i.address)):
                    explore.append(current_loc)
                continue

            # Unconditional jump: target is a leader
            if(1 in i.groups):
                if(current_loc not in explore and current_loc > 0 and rad.in_range(i.address)):
                    explore.append(current_loc)
                continue

            # call <addr> : target and next instruction are leaders
            if(2 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(i.address)):
                    explore.append(current_loc)
                continue

            # Interrupt: instruction after interrupt is a leader
            if(4 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                continue

            # Conditional jump: target and next instruction are leaders
            if(7 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(i.address)):
                    explore.append(current_loc)
                continue

            branches = True
            count_branch += 1

    if branches:
        print("Contains " + str(count_branch) + " branches.")

    if (len(explore) > 1):
        print("Size of leaders: " + str(len(explore)))

    return explore

def find_and_print(filename, explore=[]):
    """Disassemble the specified file and identify basic blocks, tracing potential
    execution flow. Addresses of an initial set of addresses to explore can be provided.
    If this set is empty, then the entry point of the ELF file is used."""

    print(f"{filename}")

    with open(filename, "rb") as f:
        # Try to decode as ELF.
        try:
            elf = ELFFile(f)
        except:
            error("Could not parse the file as ELF; cannot continue.")
            exit(1)

        # Convert and check to see if we support the file.
        bits = decoder_ring.get(elf['e_ident']['EI_CLASS'], None)
        arch = decoder_ring.get(elf['e_machine'], None)
        if arch is None:
            error(f"Unsupported architecture {elf['e_machine']}")
            exit(1)
        if bits is None:
            error(f"Unsupported bit width {elf['e_ident']['EI_CLASS']}")
            exit(1)
        # Get the .text segment's data. A more aggressive version of this would
        # grab all of the executable sections.
        section = elf.get_section_by_name('.text')
        if not section:
            error("No .text section found in file; file may be stripped or obfuscated.")
            exit(1)
        code = section.data()
        top = section.header.sh_addr
        entry = elf.header.e_entry
        offset = entry - top             # Actual entry point of the
        # Set up options for disassembly of the text segment. If you wanted to
        # provide access to all the executable sections, you might create one
        # instance for each section. Alternately you could just make a new
        # instance every time you need to switch sections.
        rad = RAD(code, arch, bits, top)
        # If no leaders were given, then add then entry point as a leader. Otherwise
        # we have nothing to do!
        if len(explore) == 0:
            explore = [entry]
        # Do both passes.
        bbs = do_pass_one(explore, rad)
        do_pass_two(bbs, rad)
        print()

def main():
    if len(sys.argv) < 2:
        print("Missing ELF File name.")
        print("Usuage: python3 entry_point.py <file_name>")
        exit(1)

    filename = sys.argv[1]
    leaders = list(map(lambda x: int(x,0), sys.argv[2:]))
    find_and_print(filename,leaders)

if __name__ == "__main__":
    main()
