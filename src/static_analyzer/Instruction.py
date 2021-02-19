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
