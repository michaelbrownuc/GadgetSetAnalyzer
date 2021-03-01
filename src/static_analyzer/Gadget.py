"""
Gadget class
"""

# Standard Library Imports

# Third Party Imports

# Local Imports
from static_analyzer.Instruction import Instruction


class Gadget(object):
    """
    The Gadget class represents a single gadget.
    """

    def __init__(self, raw_gadget):
        """
        Gadget constructor
        :param str raw_gadget: raw line output from ROPgadget
        """

        # Parse the raw line
        self.offset = raw_gadget[:raw_gadget.find(":")]
        self.instruction_string = raw_gadget[raw_gadget.find(":") + 2:]

        # Parse instruction objects
        self.instructions = []
        for instr in self.instruction_string.split(" ; "):
            self.instructions.append(Instruction(instr))

    def is_useless_op(self):
        """
        :return boolean: Returns True if the first instruction opcode is in the "useless" list, False otherwise
                         Default behavior is to consider opcodes useful unless otherwise observed.
        """
        first_opcode = self.instructions[0].opcode

        # Bulk catch for all "jump" opcodes: No reason to include the instruction, just use the suffix directly
        if first_opcode.startswith("j"):
            return True
        # Bulk catch for bounds checked jumps, same reason as above
        if first_opcode.startswith("bnd"):
            return True
        # Bulk catch for all "ret" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("ret"):
            return True
        # Bulk catch for all "iret" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("iret"):
            return True
        # Bulk catch for all "call" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("call"):
            return True

        # Useless opcodes:
        # NOP - No reason to include the instruction, just use the suffix directly
        # LJMP - Same reason as "jump" opcodes above
        useless = ["nop", "fnop", "ljmp"]
        return first_opcode in useless

    def contains_unusable_op(self):
        """
        :return boolean: Returns True if any instruction opcode is unusable.  False otherwise
                         unusable instructions are Ring-0 opcodes that trap in user mode and some other exceptional ops.
        """
        for instr in self.instructions:
            # Bulk catch for all "invalidate" opcodes: Ring-0 instructions
            if instr.opcode.startswith("inv"):
                return True
            # Bulk catch for all "Virtual-Machine" opcodes: Ring-0 instructions
            if instr.opcode.startswith("vm") and instr.opcode != "vminsd" and instr.opcode != "vminpd":
                return True
            # Bulk catch for all "undefined" opcodes
            if instr.opcode.startswith("ud"):
                return True

            # Other Ring-0 opcodes and RSM, LOCK prefix
            unusable = ["clts", "hlt", "lgdt", "lidt", "lldt", "lmsw", "ltr", "monitor", "mwait",
                        "swapgs", "sysexit", "sysreturn", "wbinvd", "wrmsr", "xsetbv", "rsm", "lock"]
            if instr.opcode in unusable:
                return True

            # Check for ring-0 operands (control, debug, and test registers)
            if instr.op1 is not None:
                if instr.op1.startswith("cr") or instr.op1.startswith("tr") or instr.op1.startswith("db"):
                    return True
            if instr.op2 is not None:
                if instr.op2.startswith("cr") or instr.op2.startswith("tr") or instr.op2.startswith("db"):
                    return True

        return False

    def is_gpi_only(self):
        """
        :return boolean: Returns True if the gadget is a single instruction and starts with 'ret', 'jmp', or 'call',
                         False otherwise
        """
        if len(self.instructions) == 1:
            opcode = self.instructions[0].opcode
            if opcode.startswith("ret") or opcode.startswith("jmp") or opcode.startswith("call"):
                return True
        return False

    def is_invalid_branch(self):
        """
        :return boolean: Returns True if the gadget is 'call' ending and the call target is a constant offset
                         False otherwise
        """
        last_instr = self.instructions[len(self.instructions)-1]
        if last_instr.opcode.startswith("call") or last_instr.opcode.startswith("jmp"):
            if Instruction.is_constant(last_instr.op1):
                return True
        return False

    def has_invalid_ret_offset(self):
        """
        :return boolean: Returns True if the gadget is 'ret' ending and contains a constant offset that is not byte
                         aligned or is greater than 32 bytes, False otherwise
        """
        last_instr = self.instructions[len(self.instructions)-1]
        if last_instr.opcode.startswith("ret") and last_instr.op1 is not None:
            offset = Instruction.get_operand_as_constant(last_instr.op1)
            if (offset % 2 != 0) or (offset > 32):
                return True

        return False

    def clobbers_created_value(self):
        """
        :return boolean: Returns True if the gadget completely overwrites the value created in the first instruction,
                         False otherwise.
        """

        first_instr = self.instructions[0]

        # Check if the first instruction creates a value or is an xchg operand (excluded as an edge case)
        if not first_instr.creates_value() or "xchg" in first_instr.opcode:
            return False

        # Check op1 to find the register family to protect
        first_family = Instruction.get_operand_register_family(first_instr.op1)

        # Most likely means first operand is a constant, exclude from analysis
        if first_family is None:
            return False

        # Iterate through intermediate instructions, determine if it overwrites protected value (or part of it)
        for i in range(1, len(self.instructions)-1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value() or "xchg" in cur_instr.opcode:
                continue

            # Check for non-static modification of the register family
            if first_family == Instruction.get_operand_register_family(cur_instr.op1):
                if cur_instr.op2 is not None and not Instruction.is_constant(cur_instr.op2):
                    return True

        return False

    def creates_unusable_value(self):
        """
        :return boolean: Returns True if the gadget creates a value in segment or extension registers, or are
                         RIP-relative, or are constant memory locations; False otherwise.
        """
        # Check if the first instruction creates a value
        first_instr = self.instructions[0]
        if first_instr.opcode in ["cmp", "test", "push"] or first_instr.op1 is None:
            return False

        # Check if first operand is not a constant and it does not belong to a recognized register family
        if not Instruction.is_constant(first_instr.op1) and \
           Instruction.get_operand_register_family(first_instr.op1) is None:
            return True

        return False


    def contains_intermediate_GPI(self):
        """
        :return boolean: Returns True if the gadget's intermediate instructions contain a GPI (or a generic interrupt),
                         False otherwise.
        """
        for i in range(len(self.instructions)-1):
            cur_opcode = self.instructions[i].opcode
            cur_target = self.instructions[i].op1
            if cur_opcode.startswith("ret") or \
               cur_opcode == "syscall" or cur_opcode == "sysenter" or cur_opcode.startswith("int") or \
               ("jmp" in cur_opcode and not Instruction.is_constant(cur_target)) or \
               ("call" in cur_opcode and not Instruction.is_constant(cur_target)):
                return True

        return False

    def clobbers_stack_pointer(self):
        """
        :return boolean: Returns True if the ROP gadget's instructions assign a non-static value to the stack pointer
                         register, False otherwise.
        """
        # Only check ROP gadgets
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("ret"):
            for i in range(len(self.instructions) - 1):
                cur_instr = self.instructions[i]
                if cur_instr.opcode not in ["cmp", "test"] and \
                   cur_instr.op1 in ["rsp", "esp", "sp", "spl"] and \
                   cur_instr.op2 is not None and not Instruction.is_constant(cur_instr.op2):
                    return True

        return False

    def clobbers_indirect_target(self):
        """
        :return boolean: Returns True if the JOP gadget's instructions assign a non-static value to the stack pointer
                         register, False otherwise.
        """
        # Get the register family of the indirect jump / call
        last_instr = self.instructions[len(self.instructions)-1]
        if last_instr.opcode.startswith("jmp") or last_instr.opcode.startswith("call"):
            family = Instruction.get_operand_register_family(last_instr.op1)

            # Check each instruction to see if it clobbers the value
            for i in range(len(self.instructions)-1):
                cur_instr = self.instructions[i]

                # First check if the instruction modifies the target
                if cur_instr.op1 in Instruction.register_families[family]:
                    # Does the instruction zeroize out the target?
                    if cur_instr.opcode == "xor" and cur_instr.op1 == cur_instr.op2:
                            return True
                    # Does the instruction perform a RIP-relative LEA into the target?
                    if cur_instr.opcode == "lea" and ("rip" in cur_instr.op2 or "eip" in cur_instr.op2):
                        return True

                    # Does the instruction load a string or a value of an input port into the target?
                    if cur_instr.opcode.startswith("lods") or cur_instr.opcode == "in":
                        return True

                    # Does the instruction overwrite the target with a static value or segment register value?
                    if "mov" in cur_instr.opcode and (Instruction.is_constant(cur_instr.op2) or
                                                     Instruction.get_operand_register_family(cur_instr.op2) == None):
                        return True
        return False

    def has_invalid_int_handler(self):
        """
        :return boolean: Returns True if the gadget's instructions assign a non-static value to the stack pointer
                         register, False otherwise.
        """
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("int") and last_instr.op1 != "0x80":
            return True

        return False

    def is_rip_relative_indirect_branch(self):
        """
        :return boolean: Returns True if the gadget is a JOP/COP gadget relying on a RIP relative indirect branch,
                         False otherwise.
        """
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("jmp") or last_instr.opcode.startswith("call"):
            if "rip" in last_instr.op1 or "eip" in last_instr.op1:
                return True

        return False

    @staticmethod
    def gadgets_equal(lhs, rhs):
        if lhs.offset == rhs.offset and lhs.instructions_raw == rhs.instructions_raw:
            return True
        else:
            return False
