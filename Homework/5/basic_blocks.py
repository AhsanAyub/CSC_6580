#!/usr/bin/env python3
#

# Importing libraries
import sys
from capstone import *
from elftools.elf.elffile import ELFFile

# Convert from ELF tools to constants used by Capstone.
decoder_ring = {
    'EM_386': CS_ARCH_X86,
    'EM_X86_64': CS_ARCH_X86,
    'ELFCLASS32': CS_MODE_32,
    'ELFCLASS64': CS_MODE_64
}

def main():
    if len(sys.argv) < 2:
        print("Missing ELF File name.")
        print("Usuage: python3 entry_point.py <file_name>")
        exit()

    for filename in sys.argv[1:]:
        print("%s:"%filename)
        try:
            with open(filename, "rb") as f:
                # Try to decode as ELF.
                try:
                    elf = ELFFile(f)
                except:
                    print("Could not parse the file as ELF; cannot continue.")
                    exit()

                # Convert and check to see if we support the file.
                bits = decoder_ring.get(elf['e_ident']['EI_CLASS'], None)
                arch = decoder_ring.get(elf['e_machine'], None)
                if arch is None:
                    print("Unsupported architecture %s" % elf['e_machine'])
                    exit()
                if bits is None:
                    print("Unsupported bit width %s" % elf['e_ident']['EI_CLASS'])
                    exit()

                # Get the .text segment's data.
                section = elf.get_section_by_name('.text')
                if not section:
                    print("No .text section found in file; file may be stripped or obfuscated.")
                    exit()
                code = section.data()   # Byte array

                # Compute the entrpy point offset to print the output
                ePoint = elf.header.e_entry                     # Get the entry point from ELF header
                textSectionHeader = section.header.sh_addr      # Get the section header
                offset = ePoint - textSectionHeader             # Actual entry point of the program

                # Check if offset is outside .text section
                if(offset < 0 or offset >= section.header.sh_size):
                    print("Entry point is not in .text section.")
                    continue

                # Set up options for disassembly of the text segment.
                md = Cs(arch, bits)
                md.skipdata = True
                md.detail = True

                # Track whether we have found branches.
                branches = False

                # Disassemble from actual entry point of the program.
                count_branch = 0
                for i in md.disasm(code[offset:], ePoint):
                    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                    if 1 in i.groups or 7 in i.groups:      # Condition to find branches
                        branches = True
                        count_branch += 1

            if branches:
                print("Contains " + str(count_branch) + " branches.")

        except:
            print("Error loading the file: " + str(filename))

if __name__ == "__main__":
    main()
