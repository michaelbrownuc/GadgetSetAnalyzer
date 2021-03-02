"""
Gadget Set Class
"""

# Standard Library Imports
import subprocess
import itertools
import os

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
        self.allGadgets = self.parse_gadgets(self.runROPgadget(filepath, "--all --multibr"))

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
        print("  INFO: Unique COP intrastack pivot gadgets: " + str(len(self.COPIntrastackPivots)))




        # TODO: Rolling marker for what has already been overhauled
        return





        # Populate COP gagdets

        self.getCOPGadgets()

        # Search for other special purpose gadgets

        self.populateSpecialJOPGadgets()


        self.populateSpecialCOPGadgets()



    @staticmethod
    def parse_gadgets(output):
        """
        Converts raw ROPgadget output into a list of Gadget objects.
        :param str output: Plain text output from run of ROPgadget
        :return: List of Gadget objects
        """
        # Iterate through each line and generate a gadget object
        gadgets = []

        lines = output.split("\n")
        for line in lines:
            # Exclude header/footer information
            if line == "Gadgets information" or \
                    line == "============================================================" or \
                    line == "" or \
                    line.startswith("Unique gadgets found"):
                continue
            else:
                gadgets.append(Gadget(line))

        return gadgets

    def runROPgadget(self, filepath, flags):
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
            elif gadget.is_JOP_dataloader():
                self.add_if_unique(gadget, self.JOPDataLoaders)
            elif gadget.is_JOP_COP_initializer():
                self.add_if_unique(gadget, self.JOPInitializers)
            elif gadget.is_JOP_trampoline():
                self.add_if_unique(gadget, self.JOPTrampolines)
            else:
                self.add_if_unique(gadget, self.JOPGadgets)
        elif gpi.startswith("call"):
            if gadget.is_JOP_COP_dispatcher():
                self.add_if_unique(gadget, self.COPDispatchers)
            elif gadget.is_COP_dataloader():
                self.add_if_unique(gadget, self.COPDataLoaders)
            elif gadget.is_JOP_COP_initializer():
                self.add_if_unique(gadget, self.COPInitializers)
            elif gadget.is_COP_strong_trampoline():
                self.add_if_unique(gadget, self.COPStrongTrampolines)
            elif gadget.is_COP_intrastack_pivot():
                self.add_if_unique(gadget, self.COPIntrastackPivots)
                print(gadget.instruction_string)
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

    def populateSpecialJOPGadgets(self):
        """
        Performs search of the JOP gadgets in this set to identify JOP special purpose gadgets
        :return: void
        """
        for gadget in self.JOPGadgets:
            first_instruction = gadget.instructions[0]
            last_instruction = gadget.instructions[len(gadget.instructions)-1]
            # Short circuit elimination of call-terminating gadgets
            if last_instruction.startswith("call"):
                continue

            # Check first instructions to identify potential data loader and initializer gadgets. We do not check all
            # otherwise we over count gadgets because ROPgadget results include all gadget suffixes of each gadget.
            if first_instruction.find("popa") > -1:
                # If a popa/popad opcode is found, this instruction can be used as an initializer gadget.
                # print("Found a JOP Initializer: " + str(gadget.instructions))
                self.JOPInitializers.append(gadget)
            elif first_instruction.find("pop ") > -1:
                # Otherwise, if a pop opcode is found, then the instruction is a data loader or trampoline candidate.
                pop_target = first_instruction[4:]
                if pop_target.find("[") == -1:
                    # Ignore pop instructions targeting memory (pop operand contains a dereference)
                    if last_instruction.find(pop_target) == -1:
                        # if pop target isn't in the last gadget, this instruction can be used as a data loader gadget.
                        # print("Found a JOP Data Loader: " + str(gadget.instructions))
                        self.JOPDataLoaders.append(gadget)
                    else:
                        # if the pop target is in the last gadget, check to see if it dereferenced. If so it is highly
                        # likely that the instruction can be used as a trampoline (exceptions are complex, non-static
                        # expressions within the dereference operation.
                        if last_instruction.find("[") > -1:
                            # Search the intermediate instructions the pop target.
                            pt_found = False
                            for i in range(1, len(gadget.instructions)-1):
                                if gadget.instructions[i].find(pop_target) > -1:
                                    # Check for use or redefinition
                                    op_split = gadget.instructions[i].find(", ")
                                    if (op_split == -1) or (gadget.instructions[i][:op_split].find(pop_target) > -1):
                                        # if the first operand (unary or binary) contains the pop_target
                                        pt_found = True
                            if pt_found is False:
                                self.JOPTrampolines.append(gadget)

            # Check last instruction for a register dereference, if so is a dispatcher candidate
            if last_instruction.find("[") > -1:
                # Generate instruction types to look for
                base_target_start = last_instruction.find("[")
                base_target = last_instruction[base_target_start + 2:base_target_start + 4]
                targets = ["r" + base_target, "e" + base_target]
                valid_opcodes = ["inc ", "dec ", "add ", "adc ", "sub ", "sbb "]
                target_operations = []
                for combo in itertools.product(valid_opcodes, targets):
                    target_operations.append(combo[0] + combo[1])
                # Check first instruction to see if it performs the required action
                for operation in target_operations:
                    operation_index = first_instruction.find(operation)
                    if operation_index > -1:
                        # If the first instruction is a target operation, do two checks
                        # 1. Check that the operation doesn't use a target in the second operand
                        used_in_second = False
                        for target in targets:
                            if first_instruction[len(operation):].find(target) > -1:
                                used_in_second = True
                        if used_in_second:
                            break

                        # 2. Check intermediate instructions for redefinition of a target
                        jt_found = False
                        for i in range(1, len(gadget.instructions) - 1):
                            for target in targets:
                                # Check for use or redefinition
                                if GadgetSet.definesTarget(gadget.instructions[i], target):
                                    jt_found = True
                        if jt_found is False:
                            self.JOPDispatchers.append(gadget)
                        break

    def populateSpecialCOPGadgets(self):
        """
        Performs search of the COP gadgets in this set to identify COP special purpose gadgets
        :return: void
        """
        for gadget in self.COPGadgets:
            first_instruction = gadget.instructions[0]
            last_instruction = gadget.instructions[len(gadget.instructions) - 1]

            # A single gadget can be used for multiple special purposes in COP techniques. We search for these in a
            # non-mutually exclusive fashion.

            # 1. Check for COP Initializer (which is also one type of Strong Trampoline Gadget)
            if first_instruction.find("popa") > -1:
                # If a popa/popad opcode is found, this instruction can be used as an initializer gadget.
                self.COPInitializers.append(gadget)
                self.COPStrongTrampolines.append(gadget)

            # 2. Deleted code that found COP Trampolines, these aren't useful gadgets per original paper.

            # 3. Check for COP Strong Trampoline (except for the special case of COP initializers)
            # Only consider instructions that start with a pop, and end with a dereference
            if first_instruction.find("pop ") > -1 and last_instruction.find("[") > -1:
                pop_targets = [first_instruction[4:]]
                call_target = last_instruction[last_instruction.find("[")+1:last_instruction.find("]")]
                is_STG = False
                reject = False

                # iterate through instructions to collect more info
                for i in range(1, len(gadget.instructions)-1):
                    current = gadget.instructions[i]

                    # Reject Case: We encounter an instruction that redefines the call target
                    if GadgetSet.definesTarget(current, call_target):
                        reject = True
                        break

                    # Accept Case: We encounter a popa(d) instruction.
                    if current.find("popa") > -1:
                        if call_target not in pop_targets:
                            isSTG = True
                            # Can't break out of loop, need to check remaining instructions for the reject case

                    # Record Case: we encounter another pop instruction, in which case we need to record data
                    if current.find("pop ") > -1:
                        pop_targets.append(current[4:])

                # Check to see if this gadget is a string of pops that makes an STG
                if (reject is not True) and (is_STG is False) and (len(pop_targets) > 1):
                    if call_target == pop_targets[len(pop_targets)-1]:
                        # Last pop must be the call target
                        is_STG = True

                if is_STG and (reject is not True):
                    self.COPStrongTrampolines.append(gadget)

            # 4. Check for COP Data Loaders. A COP Loader's first instruction is popad, call target is not \
            #    ebx/ecx/edx/edi, and intermediate instructions do not define ebx/ecx/edx.
            if first_instruction.find("popad") > -1:
                call_target = last_instruction[last_instruction.find("[") + 1:last_instruction.find("]")]
                reject = False
                # Check call target
                for target in ["ebx", "ecx", "edx", "edi"]:
                    if call_target.find(target) > -1:
                        reject = True
                        break

                if reject is not True:
                    # Check intermediate instructions
                    for i in range(1, len(gadget.instructions)-1):
                        for target in ["ebx", "ecx", "edx"]:
                            if GadgetSet.definesTarget(gadget.instructions[i], target):
                                reject = True
                                break
                        if reject:
                            break

                if reject is not True:
                    self.COPDataLoaders.append(gadget)

            # 5. Check for COP Intra-stack Pivots
            if first_instruction.find("inc esp") > -1 or first_instruction.find("add esp") > -1 or \
                    first_instruction.find("adc esp") > -1 or first_instruction.find("sbb esp") > -1 or \
                    first_instruction.find("sub esp") > -1:
                # If we find an appropriate operation, need to make the second operand isn't a pointer (if it exists)
                op_split = first_instruction.find(", ")
                if op_split == -1 or first_instruction[op_split:].find("[") == -1:
                    self.COPIntrastackPivots.append(gadget)

            # 6. Check for COP Dispatchers
            # Check last instruction for a register dereference, if so is a dispatcher candidate
            if last_instruction.find("[") > -1:
                # Generate instruction types to look for
                base_target_start = last_instruction.find("[")
                base_target = last_instruction[base_target_start + 2:base_target_start + 4]
                targets = ["r" + base_target, "e" + base_target]
                valid_opcodes = ["inc ", "dec ", "add ", "adc ", "sub ", "sbb "]
                target_operations = []
                for combo in itertools.product(valid_opcodes, targets):
                    target_operations.append(combo[0] + combo[1])
                # Check first instruction to see if it performs the required action
                for operation in target_operations:
                    operation_index = first_instruction.find(operation)
                    if operation_index > -1:
                        # If the first instruction is a target operation, do two checks
                        # 1. Check that the operation doesn't use a target in the second operand
                        used_in_second = False
                        for target in targets:
                            if first_instruction[len(operation):].find(target) > -1:
                                used_in_second = True
                        if used_in_second:
                            break

                        # 2. Check intermediate instructions for redefinition of a target
                        jt_found = False
                        for i in range(1, len(gadget.instructions) - 1):
                            for target in targets:
                                # Check for use or redefinition
                                if GadgetSet.definesTarget(gadget.instructions[i], target):
                                    jt_found = True
                        if jt_found is False:
                            self.COPDispatchers.append(gadget)
                        break

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

    @staticmethod
    def definesTarget(instruction, target):
        """
        Static method for determining if an instruction modifies the target.  The purpose of this function is to
        handle the
        :param str instruction: String representation of the instruction in question.
        :param str target: String representation of the target register.
        :return boolean: True if the instruction defines the target, False if it does not.
        """
        first_space = instruction.find(" ")

        # Check if there is no space, this indicates an instruction with no parameters.
        if first_space == -1:
            if instruction.find("popa") > -1 and target in ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]:
                return True
        # Otherwise, the instruction has operands
        else:
            op_split = instruction.find(", ")
            opcode = instruction[:first_space]
            find_index = instruction.find(target)
            # Easier to list what doesn't assign, only common x86 opcodes listed
            non_assignment_opcodes = ["push", "cmp"]

            # If the target is in the instruction and the opcode performs assignment
            if (find_index > -1) and (opcode not in non_assignment_opcodes):
                # If the instruction is unary or the target is in the first operand, then it defines the target.
                if (op_split == -1) or (find_index < op_split):
                    return True

        # Default value is to return False
        return False

    @staticmethod
    def getGadgetTypeSet(gadgetList):
        """
        Static method for generating a set of gadget strings suitable for performing set operations.
        :param Gadget[] gadgetList: A list of Gadget objects
        :return: A set of gadget strings suitable for performing set arithmetic
        """
        gadgetTypeSet = set()
        sep = "; "

        for gadget in gadgetList:
            gadgetTypeSet.add(sep.join(gadget.instructions))

        return gadgetTypeSet

    def getGadgetsFromStrings(self, gadgetStringSet, category):
        """
        Static method for finding a set of Gadget objects from instruction strings.  Used to invert conversion to set
        operable string above.
        :param str[] gadgetStringSet: A set of gadgets represented as strings (as created by getGadgetTypeSet
        :param str category: A general category for searching for the gadget objects.  Must be SYS, JOP, or COP.
        :return: A list of Gadget Objects corresponding to the input strings.
        """
        gadgetObjects = []
        objectList = None
        if category == "SYS":
            objectList = self.SysGadgets
        elif category == "JOP":
            objectList = self.JOPGadgets
        elif category == "COP":
            objectList = self.COPGadgets

        if objectList is None:
            print("Invalid Category selected for gadget search.")
            return []

        for gadgetString in gadgetStringSet:
            gadgetInstrs = gadgetString.split("; ")
            for object in objectList:
                if gadgetInstrs == object.instructions:
                    gadgetObjects.append(object)

        return gadgetObjects
