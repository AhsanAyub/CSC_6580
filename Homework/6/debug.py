#!/usr/bin/env python3
#


'''Enable debugging options based on the DEBUG environment variable.

This module checks the DEBUG environment variable for a comma-separated
list of options.  Do not include whitespace in the DEBUG value.

The following options are recognized.  Each sets a variable to True if
present, and False if not.  These variables are class variables found in
DebugOpts.

  * address ........ Print the address of each line of disassembly; sets PRINT_ADDRESSES
  * call-end ....... Treat calls as ending the basic block; sets CALL_ENDS_BB
  * fancy .......... Use specialized code to print operands; sets FANCY_OPERANDS
  * group .......... Print the group membership of instructions; sets PRINT_GROUPS
  * note ........... Print more information; sets PRINT_NOTES
  * debug .......... Print debugging information; sets DEBUGGING
  * rip ............ Resolve RIP-relative addresses and print; sets PRINT_RIP
  * syscall-end .... Treat syscalls as ending the basic block; sets SYSCALL_ENDS_BB

For example, if DebugOpts.PRINT_RIP is True, then printing the RIP value is enabled.
Otherwise DebugOpts.PRINT_RIP is False.

This module defines the debug function that take a string argument
and generates output only if the debug option was given.  It also provides
the error and note functions to format and display messages.
'''


from os import environ
from sys import stderr


# Check for debugging information.
if 'DEBUG' in environ:
    ## Split on commas, if any.  The result is a list of the strings.
    DEBUG = environ['DEBUG'].split(',')
else:
    ## DEBUG wasn't set in the environment, so use an empty list of
    ## options.
    DEBUG = []


class DebugOpts:
    DEBUGGING = 'debug' in DEBUG
    PRINT_NOTES = 'note' in DEBUG
    CALL_ENDS_BB = 'call-end' in DEBUG
    SYSCALL_ENDS_BB = 'syscall-end' in DEBUG
    PRINT_ADDRESSES = 'address' in DEBUG
    PRINT_GROUPS = 'group' in DEBUG
    PRINT_RIP = 'rip' in DEBUG
    FANCY_OPERANDS = 'fancy' in DEBUG


# See if debugging is enabled.
if DebugOpts.DEBUGGING:
    def debug(msg: str) -> None:
        '''Print the debug message.'''
        print(f"DEBUG: {msg}", flush=True)
    debug("debugging enabled")
else:
    def debug(msg: str) -> None:
        '''Print the debug message.'''
        pass

# Print notes or don't print notes.
if DebugOpts.PRINT_NOTES:
    debug("printing notes")
    def note(msg: str) -> None:
        '''Print a note to standard output.  The stream is flushed to synchonize.'''
        if DebugOpts.PRINT_NOTES:
            print(f"Note: {msg}", flush=True)
else:
    def note(msg: str) -> None:
        '''Print a note to standard output.  The stream is flushed to synchonize.'''
        pass

# Report the debugging options that are enabled.
if DebugOpts.CALL_ENDS_BB:
    debug("calls end basic blocks")
if DebugOpts.SYSCALL_ENDS_BB:
    debug("syscalls end basic blocks")
if DebugOpts.PRINT_ADDRESSES:
    debug("printing addresses")
if DebugOpts.PRINT_GROUPS:
    debug("printing instruction groups")
if DebugOpts.PRINT_RIP:
    debug("computing RIP-relative addresses")
if DebugOpts.FANCY_OPERANDS:
    debug("using fancy operand printing")

def error(msg: str) -> None:
    '''Print an error message.  The message is sent to standard error.'''
    print(f"ERROR: {msg}", file=stderr, flush=True)

if __name__ == "__main__":
    print("ERROR: This module is not meant to be run directly.")
