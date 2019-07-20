"""
Gadget class
"""

# Standard Library Imports

# Third Party Imports

# Local Imports


class Gadget(object):
    """
    The Gadget class represents a single gadget.
    """

    def __init__(self, gadget_type, offset, instructions):
        """
        Gadget constructor
        :param str type: The type of gadget (i.e. ROP, JOP, COP Trampoline, etc.)
        :param str offset: Offset location of the gadget
        :param str[] instructions
        """
        self.gadget_type = gadget_type
        self.offset = offset
        self.instructions = instructions

    @staticmethod
    def gadgetsEqual(lhs, rhs):
        if lhs.offset == rhs.offset and lhs.instructions == rhs.instructions:
            return True
        else:
            return False