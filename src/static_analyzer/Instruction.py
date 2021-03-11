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

    register_families = [["rax", "eax", "ax", "al", "ah"],  # 0
                         ["rbx", "ebx", "bx", "bl", "bh"],  # 1
                         ["rcx", "ecx", "cx", "cl", "ch"],  # 2
                         ["rdx", "edx", "dx", "dl", "dh"],  # 3
                         ["rsi", "esi", "si", "sil"],       # 4
                         ["rdi", "edi", "di", "dil"],       # 5
                         ["rbp", "ebp", "bp", "bpl"],       # 6
                         ["rsp", "esp", "sp", "spl"],       # 7
                         ["r8", "r8d", "r8w", "r8b"],       # 8
                         ["r9", "r9d", "r9w", "r9b"],       # 9
                         ["r10", "r10d", "r10w", "r10b"],   # 10
                         ["r11", "r11d", "r11w", "r11b"],   # 11
                         ["r12", "r12d", "r12w", "r12b"],   # 12
                         ["r13", "r13d", "r13w", "r13b"],   # 13
                         ["r14", "r14d", "r14w", "r14b"],   # 14
                         ["r15", "r15d", "r15w", "r15b"]]   # 15

    word_register_families = [["rax", "eax", "ax"],     # 0
                              ["rbx", "ebx", "bx"],     # 1
                              ["rcx", "ecx", "cx"],     # 2
                              ["rdx", "edx", "dx"],     # 3
                              ["rsi", "esi", "si"],     # 4
                              ["rdi", "edi", "di"],     # 5
                              ["rbp", "ebp", "bp"],     # 6
                              ["rsp", "esp", "sp"],     # 7
                              ["r8", "r8d", "r8w"],     # 8
                              ["r9", "r9d", "r9w"],     # 9
                              ["r10", "r10d", "r10w"],  # 10
                              ["r11", "r11d", "r11w"],  # 11
                              ["r12", "r12d", "r12w"],  # 12
                              ["r13", "r13d", "r13w"],  # 13
                              ["r14", "r14d", "r14w"],  # 14
                              ["r15", "r15d", "r15w"]]  # 15

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
        if self.opcode.startswith("j"):
            return False

        if self.opcode in ["cmp", "test", "push", "ljump", "out"] or self.op1 is None:
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
        # Dummy check for None or constant operands
        if operand is None or Instruction.is_constant(operand):
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

    @staticmethod
    def get_word_operand_register_family(operand):
        # Dummy check for None or constant operands
        if operand is None or Instruction.is_constant(operand):
            return None

        register = operand

        # Check if operand is a pointer, if so pull register from brackets
        pointer_loc = operand.find('[')
        if pointer_loc != -1:
            next_space_loc = operand.find(' ', pointer_loc)
            end_bracket_loc = operand.find(']')
            mult_loc = operand.find('*', pointer_loc)
            if next_space_loc == -1 and mult_loc == -1:
                register = operand[pointer_loc + 1: end_bracket_loc]
            elif mult_loc == -1:
                register = operand[pointer_loc + 1: next_space_loc]
            elif next_space_loc == -1:
                register = operand[pointer_loc + 1: mult_loc]
            else:
                end = min(next_space_loc, mult_loc)
                register = operand[pointer_loc + 1: end]

        # Iterate through families, find and return the index
        for i in range(len(Instruction.word_register_families)):
            if register in Instruction.word_register_families[i]:
                return i

        # Default return for non-integer registers, instruction pointer register, byte registers etc.
        return None

    def is_equivalent(self, rhs):
        """
        :return boolean: Returns True if the instructions are equivalent. Used for non-locality gadget metrics.
                         equivalence is defined as the exact same instruction. The only exception is if the
                         instructions are intermediate branches for multi-branch gadgets. If so, then the gadgets are
                         considered equivalent if they have the same opcode, op1 is a constant, and op2 is None.
        """
        if self.raw == rhs.raw:
            return True

        if self.opcode.startswith("j") and self.opcode == rhs.opcode and \
           Instruction.is_constant(self.op1) and Instruction.is_constant(rhs.op1) and \
           self.op2 is None and rhs.op2 is None:
            return True

        return False
