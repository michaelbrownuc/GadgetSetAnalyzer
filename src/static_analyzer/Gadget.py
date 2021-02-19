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

    @staticmethod
    def gadgets_equal(lhs, rhs):
        if lhs.offset == rhs.offset and lhs.instructions_raw == rhs.instructions_raw:
            return True
        else:
            return False
