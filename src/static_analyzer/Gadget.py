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
        """
        # TODO: DO THIS NEXT
        useless = []
        return self.instructions[0].opcode in useless

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

    @staticmethod
    def gadgets_equal(lhs, rhs):
        if lhs.offset == rhs.offset and lhs.instructions_raw == rhs.instructions_raw:
            return True
        else:
            return False
