"""
Gadget Set Class
"""

# Standard Library Imports
import subprocess

# Third Party Imports
import angr

# Local Imports
from static_analyzer.Gadget import Gadget
from static_analyzer.Instruction import Instruction


class GadgetSet(object):
    """
    The GadgetSet class is initialized from a binary file and records information about the utility and availability
    of gadgets present in the binary's encoding.
    """

    def __init__(self, name, filepath, createCFG):
        """
        GadgetSet constructor
        :param str name: Name for the gadget set
        :param str filepath: Path to the file on disk.
        :param bool createCFG: whether or not to use angr to create a CFG.
        """
        self.name = name
        self.cnt_rejected = 0
        self.cnt_duplicate = 0

        # Init the CFG with angr for finding functions
        if createCFG:
            try:
                proj = angr.Project(filepath, main_opts={'base_addr':0}, load_options={'auto_load_libs': False})
                self.cfg = proj.analyses.CFG()
                self.cfg.normalize()
            except Exception as e:
                print(str(e))
        else:
            self.cfg = None

        # Initialize functional gadget type lists
        self.allGadgets = []
        self.ROPGadgets = []
        self.JOPGadgets = []
        self.COPGadgets = []

        # Initialize special purpose gadget type lists
        self.SyscallGadgets = []
        self.JOPDispatchers = []
        self.JOPDataLoaders = []
        self.JOPInitializers = []
        self.JOPTrampolines = []
        self.COPDispatchers = []
        self.COPStrongTrampolines = []
        self.COPIntrastackPivots = []
        self.COPDataLoaders = []
        self.COPInitializers = []

        # Initialize total and average quality scores
        self.total_ROP_score = 0.0
        self.total_JOP_score = 0.0
        self.total_COP_score = 0.0
        self.averageROPQuality = 0.0
        self.averageJOPQuality = 0.0
        self.averageCOPQuality = 0.0

        # Run ROPgadget to populate total gadget set (includes duplicates and multi-branch gadgets)
        self.parse_gadgets(GadgetSet.runROPgadget(filepath, "--all --multibr"))

        # Reject unusable gadgets, sort gadgets into their appropriate category sets, score gadgets
        for gadget in self.allGadgets:
            self.analyze_gadget(gadget)

        if self.total_ROP_score != 0.0:
            self.averageROPQuality = self.total_ROP_score / len(self.ROPGadgets)
        if self.total_JOP_score != 0.0:
            self.averageJOPQuality = self.total_JOP_score / len(self.JOPGadgets)
        if self.total_COP_score != 0.0:
            self.averageCOPQuality = self.total_COP_score / len(self.COPGadgets)


        # Scan ROP gadgets to determine set expressivity
        self.practical_ROP = [False for i in range(11)]
        self.practical_ASLR_ROP = [False for i in range(35)]
        self.turing_complete_ROP = [False for i in range(17)]
        quality_threshold = 4.0

        for gadget in self.ROPGadgets:
            if gadget.score <= quality_threshold:
                self.classify_gadget(gadget)

        # Corner cases:
        # 1 If practical ROP class 4 (index 3) not satisfied by a ROP gadget, a JOP gadget targeting [rax] or [rdi] will do TODO
        # 2 If practical ROP class 6 (index 5) not satisfied by a ROP gadget, a JOP gadget targeting rax, [rax], rdi, or [rdi] will do TODO
        # 3 If practical ROP class 8 (index 7) not satisfied by a ROP Gadget, a a JOP gadget targeting [rax], [rdi], [rsi] will do TODO
        # 4 Practical ASLR ROP class 1 (index 0) can be satisfied with jumps to GPRs TODO
        # 4 Practical ASLR ROP class 2 (index 1) can be satisfied with jumps to GPRs TODO

        # TODO Add an optional summary print of counts rejected, duplicate, scores etc.  Can recover some of this from github, previous commits

    def parse_gadgets(self, output):
        """
        Converts raw ROPgadget output into a list of Gadget objects.
        :param str output: Plain text output from run of ROPgadget
        :return: List of Gadget objects
        """
        # Iterate through each line and generate a gadget object
        lines = output.split("\n")
        for line in lines:
            # Exclude header/footer information
            if line == "Gadgets information" or \
                    line == "============================================================" or \
                    line == "" or \
                    line.startswith("Unique gadgets found"):
                continue
            else:
                self.allGadgets.append(Gadget(line))

    @staticmethod
    def runROPgadget(filepath, flags):
        """
        Runs ROPgadget on the binary at filepath with flags passed.
        :param str filepath: path to binary to analyze
        :param str flags: string containing the flags for execution
        :return: Output from the ROPgadget command as a standard string, None if the data was not collected as expected.
        """

        sub = subprocess.Popen("ROPgadget --binary " + filepath + " " + flags, shell=True, stdout=subprocess.PIPE)
        subprocess_return = sub.stdout.read()
        return subprocess_return.decode("utf-8")

    def analyze_gadget(self, gadget):
        """
        Analyzes a gadget to determine its properties
        :param Gadget gadget: gadget to analyze
        :return: None, but modifies GadgetSet collections and Gadget object members
        """

        # Step 1: Eliminate useless gadgets, defined as:
        # 1) Gadgets that consist only of the GPI (SYSCALL gadgets excluded)
        # 2) Gadgets that have a first opcode that is not useful - we assume that the first instruction is part of the
        #    desired operation to be performed (otherwise attacker would just use the shorter version)
        # 3) Gadgets that end in a call/jmp <offset> (ROPgadget should not include these in the first place)
        # 4) Gadgets that create values in segment or extension registers, or are RIP-relative
        # 5) Gadgets ending in returns with offsets that are not byte aligned or greater than 32 bytes
        # 6) Gadgets containing ring-0 instructions / operands
        # 7) Gadgets that contain an intermediate GPI/interrupt (ROPgadget should not include these in the first place)
        # 8) ROP Gadgets that perform non-static assignments to the stack pointer register
        # 9) JOP/COP Gadgets that overwrite the target of and indirect branch GPI
        # 10) JOP/COP gadgets that are RIP-relative
        # 11) Syscall gadgets that end in an interrupt handler that is not 0x80 (ROPgadget should not include these)
        # 12) Gadgets that create value in the first instruction only to overwrite that value before the GPI
        # 13) Gadgets that contain intermediate static calls
        if gadget.is_gpi_only() or gadget.is_useless_op() or gadget.is_invalid_branch() or \
           gadget.creates_unusable_value() or gadget.has_invalid_ret_offset() or gadget.contains_unusable_op() or \
           gadget.contains_intermediate_GPI() or gadget.clobbers_stack_pointer() or \
           gadget.is_rip_relative_indirect_branch() or gadget.clobbers_indirect_target() or \
           gadget.has_invalid_int_handler() or gadget.clobbers_created_value() or gadget.contains_static_call():
            self.cnt_rejected += 1
            return

        # Step 2: Sort the gadget by type. Gadget type determined by GPI and secondary check for S.P. gadgets. Scoring
        #         is only performed for unique functional gadgets.
        gpi = gadget.instructions[len(gadget.instructions)-1].opcode

        if gpi.startswith("ret"):
            if self.add_if_unique(gadget, self.ROPGadgets):
                # Determine score, first checking ROP-specific side constraints
                gadget.check_sp_target_of_operation()  # increase score if stack pointer family is target of certain ops
                gadget.check_contains_leave()          # +2 if gadget contains an intermediate "leave" instruction
                gadget.check_negative_sp_offsets()     # +2 if gadget's cumulative stack pointer offsets are negative

                # Next check general side-constraints
                gadget.check_contains_conditional_op()    # increase score if gadget contains conditional operations
                gadget.check_register_ops()               # increases score for ops on value and bystander register
                gadget.check_memory_writes()              # increases score for each memory write in the gadget

                self.total_ROP_score += gadget.score

        elif gpi.startswith("jmp"):
            if gadget.is_JOP_COP_dispatcher():
                self.add_if_unique(gadget, self.JOPDispatchers)
            elif gadget.is_JOP_COP_dataloader():
                self.add_if_unique(gadget, self.JOPDataLoaders)
            elif gadget.is_JOP_initializer():
                self.add_if_unique(gadget, self.JOPInitializers)
            elif gadget.is_JOP_trampoline():
                self.add_if_unique(gadget, self.JOPTrampolines)
            else:
                if self.add_if_unique(gadget, self.JOPGadgets):
                    # Determine score, first checking JOP-specific side constraints
                    gadget.check_branch_target_of_operation()  # increase score if branch register is target of ops

                    # Next check general side-constraints
                    gadget.check_contains_conditional_op()  # increase score if gadget contains conditional operations
                    gadget.check_register_ops()  # increases score for ops on value and bystander register
                    gadget.check_memory_writes()  # increases score for each memory write in the gadget

                    self.total_JOP_score += gadget.score

        elif gpi.startswith("call"):
            if gadget.is_JOP_COP_dispatcher():
                self.add_if_unique(gadget, self.COPDispatchers)
            elif gadget.is_JOP_COP_dataloader():
                self.add_if_unique(gadget, self.COPDataLoaders)
            elif gadget.is_COP_initializer():
                self.add_if_unique(gadget, self.COPInitializers)
            elif gadget.is_COP_strong_trampoline():
                self.add_if_unique(gadget, self.COPStrongTrampolines)
            elif gadget.is_COP_intrastack_pivot():
                self.add_if_unique(gadget, self.COPIntrastackPivots)
            else:
                if self.add_if_unique(gadget, self.COPGadgets):
                    # Determine score, first checking COP-specific side constraints
                    gadget.check_branch_target_of_operation()  # increase score if branch register is target of ops

                    # Next check general side-constraints
                    gadget.check_contains_conditional_op()  # increase score if gadget contains conditional operations
                    gadget.check_register_ops()  # increases score for ops on value and bystander register
                    gadget.check_memory_writes()  # increases score for each memory write in the gadget

                    self.total_COP_score += gadget.score
        else:
            self.add_if_unique(gadget, self.SyscallGadgets)

    def add_if_unique(self, gadget, collection):
        for rhs in collection:
            if gadget.is_duplicate(rhs):
                self.cnt_duplicate += 1
                return False
        collection.append(gadget)
        return True

    def getFunction(self, rop_addr):
        rop_addr = int(rop_addr, 16)
        try:
            rop_function = self.cfg.functions.floor_func(rop_addr).name
        except Exception as e:
            print(str(e))
            return
        if rop_function:
            return rop_function
        else:
            return None

    def classify_gadget(self, gadget):
        """
        Analyzes a gadget to determine which expressivity classes it satisfies
        :param Gadget gadget: gadget to analyze
        :return: None, but modifies Gadget expressivity collections
        """
        first_instr = gadget.instructions[0]
        opcode = first_instr.opcode
        op1 = first_instr.op1
        op2 = first_instr.op2
        op1_family = Instruction.get_operand_register_family(op1)
        op2_family = Instruction.get_operand_register_family(op2)

        # TODO DELET THIS, TESTING ONLY, RESETS satisfaction array
        #self.practical_ROP = [False for i in range(11)]
        #self.turing_complete_ROP = [False for i in range(17)]
        #self.practical_ASLR_ROP = [False for i in range(35)]

        # TODO: For performance, iterate through the expressivity classes and perform analysis. Analysis rules should
        #  set as many cases as possible.
        if self.practical_ROP[0] is False:
            if opcode == "dec" and op1_family in [0, 5] and "[" not in op1:
                self.practical_ROP[0] = True

                # Also satisfies:
                self.turing_complete_ROP[0] = True
                self.practical_ASLR_ROP[9] = True

        if self.practical_ROP[1] is False:
            if opcode == "inc" and op1_family in [0, 5] and "[" not in op1:
                self.practical_ROP[1] = True

                # Also satisfies:
                self.turing_complete_ROP[0] = True
                self.practical_ASLR_ROP[8] = True

        if self.practical_ROP[2] is False:
            if opcode == "pop" and op1_family in [0, 5] and "[" not in op1:
                self.practical_ROP[2] = True

                # Also satisfies:
                self.turing_complete_ROP[1] = True
                self.practical_ASLR_ROP[5] = True

        if self.practical_ROP[3] is False:
            if (opcode == "pop" and op1_family == 4 and "[" not in op1) or \
               (opcode in ["xchg", "move"] and op1_family == 4 and op2_family in [0, 5]
                                                               and "[" not in op1 and "[" not in op2) or \
               (opcode == "lea" and op1_family == 4 and op2_family in [0, 5]
                                                    and "+" not in op2 and "-" not in op2 and "*" not in op2) or \
               (opcode == "xchg" and op1_family in [0, 5] and op2_family == 4 and "[" not in op1 and "[" not in op2):
                self.practical_ROP[3] = True

        if self.practical_ROP[4] is False:
            if opcode == "xchg" and ((op1_family == 0 and op2_family == 5) or (op2_family == 0 and op1_family == 5)) \
               and "[" not in op1 and "[" not in op2:
                self.practical_ROP[4] = True

        if self.practical_ROP[5] is False:
            if opcode == "push" and op1_family in [0, 4, 5] and "[" not in op1:
                self.practical_ROP[5] = True

        if self.practical_ROP[6] is False:
            if opcode in ["clc", "sahf"] or \
               (opcode in ["test", "add", "adc", "sub", "sbb", "and", "or", "xor", "cmp"] and
               op1_family in [0, 4, 5] and op2_family in [0, 4, 5] and "[" not in op1 and "[" not in op2):
                self.practical_ROP[6] = True

                # Also satisfies:
                self.turing_complete_ROP[7] = True
                self.practical_ASLR_ROP[4] = True

        if self.practical_ROP[7] is False:
            if (opcode.startswith("stos") or opcode in ["mov", "add", "or"]) and "[" in op1 and "+" not in op1 and \
               "-" not in op1 and "*" not in op1 and op1_family in [0, 4, 5] and op2_family in [0, 4, 5] and \
               op1_family != op2_family:
                self.practical_ROP[7] = True

                # Also satisfies:
                self.turing_complete_ROP[6] = True
                self.practical_ASLR_ROP[2] = True

        if self.practical_ROP[8] is False:
            if (opcode.startswith("lods") or opcode in ["mov", "add", "adc", "sub", "sbb", "and", "or", "xor"]) and \
               "[" in op2 and "+" not in op2 and "-" not in op2 and "*" not in op2 and op1_family in [0, 4, 5] and \
               op2_family in [0, 4, 5] and op1_family != op2_family:
                self.practical_ROP[8] = True

                # Also satisfies:
                self.turing_complete_ROP[5] = True
                self.practical_ASLR_ROP[1] = True

        # NOTE: Single rule for two classes
        if self.practical_ROP[9] is False or self.practical_ASLR_ROP[7] is False:
            if opcode == "leave":
                self.practical_ROP[9] = True
                self.practical_ASLR_ROP[7] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class LEAVE")

        if self.practical_ROP[10] is False:
            if (opcode == "pop" and op1_family == 6 and "[" not in op1) or \
               (opcode == "xchg" and op1_family is not None and op2_family is not None and op1_family != op2_family
                                 and (op1_family == 6 or op2_family == 6) and "[" not in op1 and "[" not in op2) or \
               (opcode in ["add", "adc", "sub", "sbb"] and "[" not in op1 and op1_family == 6 and
               op2_family not in [None, 6] and "+" not in op2 and "-" not in op2 and "*" not in op2):
                self.practical_ROP[10] = True

        if self.turing_complete_ROP[0] is False:
            if opcode in ["inc", "dec"] and op1_family not in [None, 7] and "+" not in op1 and "-" not in op1 and \
               "*" not in op1:
                self.turing_complete_ROP[0] = True

        if self.turing_complete_ROP[1] is False:
            if opcode == "pop" and op1_family not in [None, 7] and "[" not in op1:
                self.turing_complete_ROP[1] = True

        if self.turing_complete_ROP[2] is False:
            if opcode in ["add", "adc", "sub", "sbb"] and op1_family not in [None, 7] and "+" not in op1 and \
                    "-" not in op1 and "*" not in op1 and op2_family not in [None, 7] and "+" not in op2 and \
                    "-" not in op2 and "*" not in op2 and op1_family != op2_family:
                self.turing_complete_ROP[2] = True

        if self.turing_complete_ROP[3] is False:
            if (opcode == "xor" and op1_family not in [None, 7] and "+" not in op1 and "-" not in op1 and "*" not in op1
               and op2_family not in [None, 7] and "+" not in op2 and "-" not in op2 and "*" not in op2
               and op1_family != op2_family) or \
               (opcode in ["neg", "not"] and op1_family not in [None, 7] and "+" not in op1 and "-" not in op1
               and "*" not in op1):
                self.turing_complete_ROP[3] = True

        if self.turing_complete_ROP[4] is False:
            if opcode in ["and", "or"] and op1_family not in [None, 7] and "+" not in op1 and \
                    "-" not in op1 and "*" not in op1 and op2_family not in [None, 7] and "+" not in op2 and \
                    "-" not in op2 and "*" not in op2 and op1_family != op2_family:
                self.turing_complete_ROP[4] = True

        if self.turing_complete_ROP[5] is False:
            if (opcode.startswith("lods") or opcode in ["mov", "add", "adc", "sub", "sbb", "and", "or", "xor"]) and \
               "[" in op2 and "+" not in op2 and "-" not in op2 and "*" not in op2 and \
               op1_family not in [None, 7] and op2_family not in [None, 7] and op1_family != op2_family:
                self.turing_complete_ROP[5] = True

        if self.turing_complete_ROP[6] is False:
            if (opcode.startswith("stos") or opcode in ["mov", "add", "or"]) and "[" in op1 and "+" not in op1 and \
               "-" not in op1 and "*" not in op1 and op1_family not in [None, 7] and op2_family not in [None, 7] and \
               op1_family != op2_family:
                self.turing_complete_ROP[6] = True

        if self.turing_complete_ROP[7] is False:
            if opcode in ["clc", "sahf"] or \
               (opcode in ["test", "add", "adc", "sub", "sbb", "and", "or", "xor", "cmp"] and
               op1_family not in [None, 7] and op2_family not in [None, 7] and "+" not in op1 and "-" not in op1 and
               "*" not in op1 and "+" not in op2 and "-" not in op2 and "*" not in op2 and op1_family != op2_family):
                self.turing_complete_ROP[7] = True

        if self.turing_complete_ROP[8] is False:
            if opcode in ["add", "adc", "sub", "sbb"] and "[" not in op2 and op2_family == 7 and \
               op1_family not in [None, 7] and "+" not in op1 and "-" not in op1 and "*" not in op1:
                self.turing_complete_ROP[8] = True

        if self.turing_complete_ROP[9] is False:
            if (opcode == "pop" and op1_family == 7 and "[" not in op1) or \
               (opcode == "xchg" and op1_family is not None and op2_family is not None and op1_family != op2_family
                                 and (op1_family == 7 or op2_family == 7) and "[" not in op1 and "[" not in op2) or \
               (opcode in ["add", "adc", "sub", "sbb"] and "[" not in op1 and op1_family == 7 and
               op2_family not in [None, 7] and "+" not in op2 and "-" not in op2 and "*" not in op2):
                self.turing_complete_ROP[9] = True

        if self.turing_complete_ROP[10] is False:
            if opcode in ["lahf", "pushf"] or \
               (opcode in ["adc", "sbb"] and op1_family not in [None, 7] and op2_family not in [None, 7] and
               "+" not in op1 and "-" not in op1 and "*" not in op1 and
               "+" not in op2 and "-" not in op2 and "*" not in op2 and op1_family != op2_family):
                self.turing_complete_ROP[10] = True

        # Next 6 classes have common and very specific requirements, check once
        if opcode == "xchg" and "[" not in op1 and "[" not in op2 and op1_family != op2_family:
            if self.turing_complete_ROP[11] is False:
                if op1_family in [0, 1] and op2_family in [0, 1]:
                    self.turing_complete_ROP[11] = True

            if self.turing_complete_ROP[12] is False:
                if op1_family in [0, 2] and op2_family in [0, 2]:
                    self.turing_complete_ROP[12] = True

            if self.turing_complete_ROP[13] is False:
                if op1_family in [0, 3] and op2_family in [0, 3]:
                    self.turing_complete_ROP[13] = True

            if self.turing_complete_ROP[14] is False:
                if op1_family in [0, 6] and op2_family in [0, 6]:
                    self.turing_complete_ROP[14] = True

            if self.turing_complete_ROP[15] is False:
                if op1_family in [0, 4] and op2_family in [0, 4]:
                    self.turing_complete_ROP[15] = True

            if self.turing_complete_ROP[16] is False:
                if op1_family in [0, 5] and op2_family in [0, 5]:
                    self.turing_complete_ROP[16] = True

        if self.practical_ASLR_ROP[0] is False:
            if opcode == "push" and op1_family not in [None, 6, 7] and "[" not in op1:
                self.practical_ASLR_ROP[0] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class JMP/PSH <GPR>")

        if self.practical_ASLR_ROP[1] is False:
            if (opcode.startswith("lods") or opcode in ["mov", "add", "adc", "sub", "sbb", "and", "or", "xor"]) and \
               "[" in op2 and "+" not in op2 and "-" not in op2 and "*" not in op2 and \
               op1_family not in [None, 7] and op2_family not in [None, 6, 7] and op1_family != op2_family:
                self.practical_ASLR_ROP[1] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class LOAD <GPR> [<GPR>]")

        if self.practical_ASLR_ROP[2] is False:
            if (opcode.startswith("stos") or opcode == "mov") and "[" in op1 and "+" not in op1 and \
               "-" not in op1 and "*" not in op1 and op1_family not in [None, 7] and op2_family not in [None, 7] and \
               op1_family != op2_family:
                self.practical_ASLR_ROP[2] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class STORE [<GPR>] <GPR>")

        if self.practical_ASLR_ROP[3] is False:
            #TODO ESP LOAD
            pass

        if self.practical_ASLR_ROP[4] is False:
            if opcode in ["clc", "sahf"] or \
               (opcode in ["test", "add", "adc", "sub", "sbb", "and", "or", "xor", "cmp"] and
               op1_family not in [None, 7] and op2_family not in [None, 7] and "[" not in op1 and "[" not in op2):
                self.practical_ASLR_ROP[4] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class CLEAR FLAGS")

        if self.practical_ASLR_ROP[5] is False:
            if opcode == "pop" and op1_family in [0, 4, 5] and "[" not in op1:
                self.practical_ASLR_ROP[5] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class POP AX/SI/DI")

        if self.practical_ASLR_ROP[6] is False:
            if opcode == "pop" and op1_family in [1, 2, 3, 6] and "[" not in op1:
                self.practical_ASLR_ROP[5] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class POP CX/CX/DX/BP")

        # NOTE class 8 (index 7) is combined above

        if self.practical_ASLR_ROP[8] is False:
            if opcode == "inc" and op1_family not in [None, 7] and "[" not in op1:
                self.practical_ASLR_ROP[8] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class INC <GPR>")

        if self.practical_ASLR_ROP[9] is False:
            if opcode == "dec" and op1_family not in [None, 7] and "[" not in op1:
                self.practical_ASLR_ROP[9] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class DEC <GPR>")

        if self.practical_ASLR_ROP[10] is False:
            if opcode in ["add", "adc", "sub", "sbb"] and op1_family not in [None, 7] and "[" not in op1 and \
               op2_family not in [None, 7] and "[" not in op2 and op1_family != op2_family:
                self.practical_ASLR_ROP[10] = True
                print("Instr: " + first_instr.raw + " satisfies practical ASLR ROP class [ADD|SDC|SUB|SBB] <GPR> <GPR>")

        if self.practical_ASLR_ROP[11] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[12] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[13] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[14] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[15] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[16] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[17] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[18] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[19] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[20] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[21] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[22] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[23] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[24] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[25] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[26] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[27] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[28] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[29] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[30] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[31] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[32] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[33] is False:
            #TODO
            pass

        if self.practical_ASLR_ROP[34] is False:
            #TODO
            pass
