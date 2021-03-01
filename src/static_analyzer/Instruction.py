"""
Instruction class
"""

# Standard Library Imports

# Third Party Imports

# Local Imports


class Instruction(object):
    """
    The Instruction class represents a single instruction within a Gadget.
    """

    register_families = [["rax", "eax", "ax", "al", "ah"],
                         ["rbx", "ebx", "bx", "bl", "bh"],
                         ["rcx", "ecx", "cx", "cl", "ch"],
                         ["rdx", "edx", "dx", "dl", "dh"],
                         ["rsi", "esi", "si", "sil"],
                         ["rdi", "edi", "di", "dil"],
                         ["rbp", "ebp", "bp", "bpl"],
                         ["rsp", "esp", "sp", "spl"],
                         ["r8", "r8d", "r8w", "r8b"],
                         ["r9", "r9d", "r9w", "r9b"],
                         ["r10", "r10d", "r10w", "r10b"],
                         ["r11", "r11d", "r11w", "r11b"],
                         ["r12", "r12d", "r12w", "r12b"],
                         ["r13", "r13d", "r13w", "r13b"],
                         ["r14", "r14d", "r14w", "r14b"],
                         ["r15", "r15d", "r15w", "r15b"]]

    def __init__(self, raw_instr):
        """
        Gadget constructor
        :param str raw_instr: the raw instruction
        """

        self.raw = raw_instr

        self.opcode = None
        self.op1 = None
        self.op2 = None

        # Look for a space, if not found this gadget takes no operands
        spc_idx = raw_instr.find(" ")
        if spc_idx == -1:
            self.opcode = raw_instr
        # otherwise, opcode ends at space and need to parse operand(s)
        else:
            self.opcode = raw_instr[:spc_idx]
            comma_idx = raw_instr.find(", ")

            # If no space found, then there is only one operand and it is what is left
            if comma_idx == -1:
                self.op1 = raw_instr[spc_idx+1:]
            # Otherwise, op1 ends at comma and rest is op2
            else:
                self.op1 = raw_instr[spc_idx+1:comma_idx]
                self.op2 = raw_instr[comma_idx+2:]

        # Error checks on parsing
        if self.opcode is None:
            print("  ERROR parsing gadget, no opcode found.")

        test_str = self.opcode

        if self.op1 is not None:
            test_str = test_str + " " + self.op1

        if self.op2 is not None:
            test_str = test_str + ", " + self.op2

        if raw_instr != test_str:
            print("  ERROR parsing gadget, parsed gadget doesn't match raw input.")

    def creates_value(self):
        """
        :return boolean: Returns True if the gadget creates a value.
        """
        if self.opcode in ["cmp", "test", "push"] or self.op1 is None:
            return False

        return True

    @staticmethod
    def is_hex_constant(operand):
        if operand is None:
            return False

        try:
            int(operand, 16)
            return True
        except ValueError:
            return False


    @staticmethod
    def is_dec_constant(operand):
        if operand is None:
            return False

        try:
            int(operand)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_constant(operand):
        if operand is None:
            return False

        return Instruction.is_hex_constant(operand) or Instruction.is_dec_constant(operand)

    @staticmethod
    def get_operand_as_constant(operand):
        if Instruction.is_hex_constant(operand):
            return int(operand, 16)
        elif Instruction.is_dec_constant(operand):
            return int(operand)
        else:
            print("  ERROR: Operand is not a hex or decimal constant. " + operand)

    @staticmethod
    def get_operand_register_family(operand):
        # Dummy check for constant operands
        if Instruction.is_constant(operand):
            return None

        register = operand

        # Check if operand is a pointer, if so pull register from brackets
        pointer_loc = operand.find('[')
        if pointer_loc != -1:
            next_space_loc = operand.find(' ', pointer_loc)
            end_bracket_loc = operand.find(']')
            mult_loc = operand.find('*', pointer_loc)
            if next_space_loc == -1 and mult_loc == -1:
                register = operand[pointer_loc+1 : end_bracket_loc]
            elif mult_loc == -1:
                register = operand[pointer_loc + 1: next_space_loc]
            elif next_space_loc == -1:
                register = operand[pointer_loc + 1: mult_loc]
            else:
                end = min(next_space_loc, mult_loc)
                register = operand[pointer_loc+1 : end]

        # Iterate through families, find and return the index
        for i in range(len(Instruction.register_families)):
            if register in Instruction.register_families[i]:
                return i

        # Default return for non-integer registers, instruction pointer register, etc.
        return None
