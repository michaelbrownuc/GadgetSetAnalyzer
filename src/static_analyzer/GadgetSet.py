"""
Gadget Set Class
"""

# Standard Library Imports
import subprocess

# Third Party Imports
import angr

# Local Imports
from static_analyzer.Gadget import Gadget


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

        # Initialize average quality scores
        self.averageROPQuality = 0.0
        self.averageJOPQuality = 0.0
        self.averageCOPQuality = 0.0
        self.averageSyscallQuality = 0.0
        self.averageJOPDispatcherQuality = 0.0
        self.averageJOPDataLoaderQuality = 0.0
        self.averageJOPInitializerQuality = 0.0
        self.averageJOPTrampolineQuality = 0.0
        self.averageCOPDispatcherQuality = 0.0
        self.averageCOPStrongTrampolineQuality = 0.0
        self.averageCOPIntrastackPivotQuality = 0.0
        self.averageCOPDataLoaderQuality = 0.0
        self.averageCOPInitializerQuality = 0.0

        # Run ROPgadget to populate total gadget set (includes duplicates and multi-branch gadgets)
        self.parse_gadgets(GadgetSet.runROPgadget(filepath, "--all --multibr"))

        # Reject unusable gadgets, sort gadgets into their appropriate category sets, score gadgets, classify gadgets
        for gadget in self.allGadgets:
            self.analyze_gadget(gadget)

        # TODO Delete this at some point
        print("  INFO: Total number of all gadgets: " + str(len(self.allGadgets)))
        print("  INFO: Number of rejected gadgets: " + str(self.cnt_rejected))
        print("  INFO: Number of duplicate gadgets: " + str(self.cnt_duplicate))
        print("  INFO: Unique ROP gadgets: " + str(len(self.ROPGadgets)))
        print("  INFO: Unique JOP gadgets: " + str(len(self.JOPGadgets)))
        print("  INFO: Unique COP gadgets: " + str(len(self.COPGadgets)))
        print("  INFO: Unique SYS gadgets: " + str(len(self.SyscallGadgets)))
        print("  INFO: Unique JOP dispatcher gadgets: " + str(len(self.JOPDispatchers)))
        print("  INFO: Unique JOP initializer gadgets: " + str(len(self.JOPInitializers)))
        print("  INFO: Unique JOP dataloader gadgets: " + str(len(self.JOPDataLoaders)))
        print("  INFO: Unique JOP trampoline gadgets: " + str(len(self.JOPTrampolines)))
        print("  INFO: Unique COP dispatcher gadgets: " + str(len(self.COPDispatchers)))
        print("  INFO: Unique COP initializer gadgets: " + str(len(self.COPInitializers)))
        print("  INFO: Unique COP dataloader gadgets: " + str(len(self.COPDataLoaders)))
        print("  INFO: Unique COP strong trampoline gadgets: " + str(len(self.COPStrongTrampolines)))
        print("  INFO: Unique COP intrastack pivot gadgets: " + str(len(self.COPIntrastackPivots)))

        # TODO: Rolling marker for what has already been overhauled
        return

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
        if gadget.is_gpi_only() or gadget.is_useless_op() or gadget.is_invalid_branch() or \
           gadget.creates_unusable_value() or gadget.has_invalid_ret_offset() or gadget.contains_unusable_op() or \
           gadget.contains_intermediate_GPI() or gadget.clobbers_stack_pointer() or \
           gadget.is_rip_relative_indirect_branch() or gadget.clobbers_indirect_target() or \
           gadget.has_invalid_int_handler() or gadget.clobbers_created_value():
            self.cnt_rejected += 1
            return


        # Step 2: Determine the gadget type, determined by:
        # 1) GPI - rets = ROP, Jmps/Calls = JOP, Calls = COP, Others = SYSCALL
        # 2) If a JOP/COP gadget, perform secondary Special Purpose gadget check. If qualified, add to that set instead
        gpi = gadget.instructions[len(gadget.instructions)-1].opcode

        if gpi.startswith("ret"):
            self.add_if_unique(gadget, self.ROPGadgets)
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
                self.add_if_unique(gadget, self.JOPGadgets)
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
                self.add_if_unique(gadget, self.COPGadgets)
        else:
            self.add_if_unique(gadget, self.SyscallGadgets)

        # Step 3: Determine the gadget score, which starts at 0 and is incremented by:
        # 1) TODO list out gality criterion here

        # Step 4: Calculate average quality score for sets


    def add_if_unique(self, gadget, collection):
        for rhs in collection:
            if gadget.is_duplicate(rhs):
                self.cnt_duplicate += 1
                return
        collection.append(gadget)

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
