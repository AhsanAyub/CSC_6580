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
    bbs_index = 1
    final_index = len(bbs)
    print("block at: " + str(hex(bbs[0])))
    #print("block at: " + str(bbs[0]))
    for i in rad.md.disasm(rad.code, bbs[0]):
        if(i.address >= bbs[bbs_index]):
            bbs_index = bbs_index + 1
            if(bbs_index > final_index):
                print("next: unknown")
                exit(1)
            #print("next: " + str(bbs[bbs_index - 1]))
            print("next: " + str(hex(bbs[bbs_index - 1])))
            print("\nblock at: " + str(hex(bbs[bbs_index - 1])))
            #print("block at: " + str(bbs[bbs_index - 1]))

        # Unconditional jump instruction to break out of loop
        if ((1 in i.groups) and (7 in i.groups)) and (i.address < bbs[bbs_index] and i.address >= bbs[bbs_index-1]):
            #print("\t%s:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            print("\t%s\t%s" %(i.mnemonic, i.op_str))
            bbs_index = bbs_index + 1
            if(bbs_index > final_index):
                print("next: unknown")
                exit(1)
            '''print("true: " + str(int(i.op_str, 0)))
            print("false: " + str(bbs[bbs_index - 1]))'''
            print("true: " + str(i.op_str))
            print("false: " + str(hex(bbs[bbs_index - 1])))
            #print("block at: " + str(bbs[bbs_index - 1]))
            print("\nblock at: " + str(hex(bbs[bbs_index - 1])))

        # Return instruction to break out of loop
        if (3 in i.groups) and (i.address < bbs[bbs_index] and i.address >= bbs[bbs_index-1]):
            #print("\t%s:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            print("\t%s\t%s" %(i.mnemonic, i.op_str))
            bbs_index = bbs_index + 1
            if(bbs_index > final_index):
                print("next: unknown")
                exit(1)
            #print("next: " + str(bbs[bbs_index - 1]))
            print("next: " + str(hex(bbs[bbs_index - 1])))
            print("\nblock at: " + str(hex(bbs[bbs_index - 1])))
            #print("block at: " + str(bbs[bbs_index - 1]))

        # hlt instruction to break out from basic block
        if (i.mnemonic == "hlt") and (i.address < bbs[bbs_index] and i.address >= bbs[bbs_index-1]):
            #print("\t%s:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            print("\t%s\t%s" %(i.mnemonic, i.op_str))
            bbs_index = bbs_index + 1
            if(bbs_index >= final_index):
                print("next: unknown")
                exit(1)
            #print("next: " + str(bbs[bbs_index - 1]))
            print("next: " + str(hex(bbs[bbs_index - 1])))
            print("\nblock at: " + str(hex(bbs[bbs_index - 1])))
            #print("block at: " + str(bbs[bbs_index - 1]))

        # Print if the address falls into the space
        try:
            if(i.address < bbs[bbs_index] and i.address >= bbs[bbs_index-1]):
                #print("\t%s:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                print("\t%s\t%s" %(i.mnemonic, i.op_str))
        except:
            break

        #print("\t0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    return bbs_index

def do_pass_one(explore, rad):
    # Track whether we have found branches.
    branches = False
    count_branch = 0

    # Iterating through the loop
    for i in rad.md.disasm(rad.code, rad.offset):
        if 1 in i.groups or 7 in i.groups:      # Condition to find branches
            if(len(i.operands) > 0 and is_imm(i.operands[0])):
            #if(len(i.operands) == 1 and (is_imm(i.operands[0]) or is_reg(i.operands[0]))):
                current_loc = int(i.op_str, 0)
            else:
                current_loc = -1
            next_loc = i.address + i.size

            # Conditional jump: target and next instruction are leaders
            if(1 in i.groups and 7 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(current_loc)):
                    explore.append(current_loc)
                continue

            # call <addr> : target and next instruction are leaders
            if(2 in i.groups and 7 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(current_loc)):
                    explore.append(current_loc)
                continue

            # Unconditional jump: target is a leader
            if(1 in i.groups):
                if(current_loc not in explore and current_loc > 0 and rad.in_range(current_loc)):
                    explore.append(current_loc)
                continue

            # call <addr> : target and next instruction are leaders
            if(2 in i.groups):
                if(next_loc not in explore):
                    explore.append(next_loc)
                if(current_loc not in explore and current_loc > 0 and rad.in_range(current_loc)):
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
                if(current_loc not in explore and current_loc > 0 and rad.in_range(current_loc)):
                    explore.append(current_loc)
                continue

            branches = True
            count_branch += 1

    '''if branches:
        print("Contains " + str(count_branch) + " branches.")

    if (len(explore) > 1):
        print("Size of leaders: " + str(len(explore)))'''

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
        explored_index = do_pass_two(bbs, rad)
        if explored_index <= len(bbs):
            print("next: unknown")
        '''print(explored_index)
        print(len(bbs))
        print(hex(rad.offset + rad.size))'''

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
