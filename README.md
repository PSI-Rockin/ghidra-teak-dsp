# Ghidra Teak DSP

A WIP Ghidra plugin for the 3DS/DSi XpertTeak. Most of the Teak instruction set has been implemented, enough to fully disassemble both the 3DS Home Menu's and Sound App's firmwares. Accesses to unimplemented context registers such as ar/arp are represented through pcodeops whenever possible. Includes a CDC/DSP1 binary loader.

## Known issues
* Many instructions not present within the above firmwares are still missing from the specification
* Does not properly handle middle-endianness for 32-bit loads/stores. As far as I can tell, Ghidra has no way to fully support this
* Cannot properly detect push sv -> ret sequences used for function pointers (might be possible to handle with a script?)
* stepi0/stepj0 stepping not implemented (didn't find any sequences to test on...)
* No sat/sata-based saturation (lim is implemented as a pcodeop)
* No modulo/address bit-reverse
* ArStep/ArpStep configs are hardcoded
* Broken call analysis in certain functions, causing the decompiler to display stack writes
* Decompilation can be rather ugly due to lots of sign-extension/zero-extension IR ops

## AI disclosure
AI was used in the making of this project for the following things:
* Creating the initial script for CDC loading
* Suggesting ideas for implementing certain features
* Reviewing and finding bugs in the specification

Everything else, including writing the documentation and the SLEIGH specification, was done by a human.
