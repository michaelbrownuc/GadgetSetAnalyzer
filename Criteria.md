# GSA Gadget Criteria Reference
This file contains reference information on the criteria GSA uses to (1) eliminate gadgets from consideration in the set and (2) score the remaining gadgets in theset for qaulity. 


## Elimination Criteria

  1. Gadgets that consist only of the GPI (SYSCALL gadgets excluded)
  2. Gadgets that have a first opcode that is not useful - we assume that the first instruction is part of the
     desired operation to be performed (otherwise attacker would just use the shorter version)
  3. Gadgets that end in a call/jmp <offset> (ROPgadget should not include these in the first place)
  4. Gadgets that create values in segment or extension registers, or are RIP-relative
  5. Gadgets ending in returns with offsets that are not byte aligned or greater than 32 bytes
  6. Gadgets containing ring-0 instructions / operands
  7. Gadgets that contain an intermediate GPI/interrupt (ROPgadget should not include these in the first place)
  8. ROP Gadgets that perform non-static assignments to the stack pointer register
  9. JOP/COP Gadgets that overwrite the target of and indirect branch GPI
  10. JOP/COP gadgets that are RIP-relative
  11. Syscall gadgets that end in an interrupt handler that is not 0x80 (ROPgadget should not include these)
  12. Gadgets that create value in the first instruction only to overwrite that value before the GPI
  13. Gadgets that contain intermediate static calls


## Scoring Criteria
  
### General
  1. (+3.0) Gadget has intermediate conditional jump 
  2. (+2.0) Gadget has intermediate conditional move or exchange
  3. (+1.0) Gadget has intermediate set instruction
  4. (+1.5) Gadget has intermediate static shift/rotate operation on value-carrying register
  5. (+1.0) Gadget has intermediate static non-shift/rotate operation on value-carrying register
  6. (+1.0) Gadget has intermediate run-time modification to a bystander register
  7. (+0.5) Gadget has intermediate static modification to a bystander register
  8. (+1.0) Gadget has intermediate instruction that stores value in memory location
  
### ROP only
  1. (+2.0) Gadget contains intermediate leave instruction
  2. (+2.0) Gadget's cumulative stack pointer offsets are negative
  3. 
  
### JOP only
  
### COP only

