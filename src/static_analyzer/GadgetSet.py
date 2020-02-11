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
    The GadgetSet class is initialized from a binary file and contains information derived from static analysis tools.
    """

    galityPath = "/usr/local/gality/bin/"

    def __init__(self, name, filepath, createCFG):
        """
        GadgetSet constructor
        :param str name: Name for the gadget set
        :param str filepath: Filepath of the file on disk to debloat.
        :param bool createCFG: whether or not to use angr to create a CFG.
        """

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

        self.name = name
        self.totalUniqueGadgets = set()

        # Run ROPgadget to populate ROP, JOP, and Syscall gadgets
        self.ROPGadgets = self.parseGadgets("ROP", self.runROPgadget(filepath, "--nojop --nosys"))
        self.JOPGadgets = self.parseGadgets("JOP", self.runROPgadget(filepath, "--norop --nosys"))
        self.SysGadgets = self.parseGadgets("Syscall", self.runROPgadget(filepath, "--norop --nojop"))

	# Run Gality (GT Version) to collect ROP / JOP / COP useful gadget counts and average quality
        self.keptQualityROPGadgets = 0
        self.keptQualityJOPGadgets = 0
        self.keptQualityCOPGadgets = 0
        self.averageROPQuality = 0.0
        self.averageJOPQuality = 0.0
        self.averageCOPQuality = 0.0
        self.runGality(filepath)

        # Filter JOP gadgets
        self.filterJOPGadgets()

        # Populate COP gagdets
        self.COPGadgets = []
        self.getCOPGadgets()

        # Search for other special purpose gadgets
        self.JOPDispatchers = []
        self.JOPDataLoaders = []
        self.JOPInitializers = []
        self.JOPTrampolines = []
        self.populateSpecialJOPGadgets()

        self.COPDispatchers = []
        self.COPStrongTrampolines = []
        self.COPIntrastackPivots = []
        self.COPDataLoaders = []
        self.COPInitializers = []
        self.populateSpecialCOPGadgets()

        # Run microgadget scanner
        self.simpleTuringCompleteClasses = self.parseClasses(self.runROPgadget(filepath, "--nojop --nosys --microgadgets"))

    def parseGadgets(self, gadget_type, output):
        """
        Converts raw ROPGadget output into a list of Gadget objects.
        :param str output: Plain text output from run of ROPGagdet
        :param str gadget_type: String representing the type of gadgets in this collection.
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
            # Split gadgets into constituent parts
            else:
                offset = line[:line.find(":")]
                gadget_string = line[line.find(":") + 2:]
                instructions = gadget_string.split(" ; ")
                gadgets.append(Gadget(gadget_type, offset, instructions))
                self.totalUniqueGadgets.add(gadget_string)

        return gadgets

    def runROPgadget(self, filepath, flags):
        """
        Runs ROPGadget on the binary at filepath with flags passed.
        :param str filepath: path to binary to analyze
        :param str flags: string containing the flags for execution
        :return: Output from the ROPgadget command as a standard string, None if the data was not collected as expected.
        """
        bytestr = None
        try:
            bytestr = subprocess.check_output("ROPgadget --binary " + filepath + " " + flags, shell=True)
        except subprocess.CalledProcessError as CPE:
            print("Error in running ROPgadget with flags:" + flags)
            print(CPE.output)

        # Convert output to standard string.
        return bytestr.decode("utf-8")

    def runGality(self, filepath):
        """
        Runs Gality on the total ROPgadget output for the file specified at the filepath. Also parses the produced file
        and sets the appropriate member variables.
        :param filepath: path to binary to analyze
        :return: None
        """
        # Run ROPgadget with all engines enabled, and save file to a temp file in the current directory. Then run gality
        # on that file, saving a new temp file.
        rg_output = self.runROPgadget(filepath, "")

        try:
            file = open("gality_temp_input_file.txt", "w")
            file.write(rg_output)
            file.close()
        except OSError as osErr:
            print(osErr)

        subprocess.run("java -cp " + self.galityPath +
                        " gality.Program gality_temp_input_file.txt gality_temp_output_file.txt", shell=True)

        # Open the temp file, read the lines.
        file_lines = []

        try:
            file = open("gality_temp_output_file.txt", "r")
            file_lines = file.readlines()
            file.close()
        except OSError as osErr:
            print(osErr)

        # Delete the temp files.
        try:
            os.remove("gality_temp_input_file.txt")
            os.remove("gality_temp_output_file.txt")
        except OSError as osErr:
            print(osErr)

        # Parse the lines into the values we want to keep.
        for line in file_lines:
            if line.find("Kept") > -1:
                if line.find("ROP") > -1:
                    self.keptQualityROPGadgets = int(line[5:line.find("ROP")-1])
                elif line.find("JOP") > -1:
                    self.keptQualityJOPGadgets = int(line[5:line.find("JOP")-1])
                elif line.find("COP") > -1:
                    self.keptQualityCOPGadgets = int(line[5:line.find("COP")-1])
                else:
                    print("Unexpected line encountered while parsing gality results: " + line)

            if line.find("Average") > -1:
                if line.find("ROP") > -1:
                    self.averageROPQuality = float(line[line.find(": ") + 2:])
                elif line.find("JOP") > -1:
                    self.averageJOPQuality = float(line[line.find(": ") + 2:])
                elif line.find("COP") > -1:
                    self.averageCOPQuality = float(line[line.find(": ") + 2:])
                else:
                    print("Unexpected line encountered while parsing gality results: " + line)


    def filterJOPGadgets(self):
        """
        Corrects for an issue in ROPGadget that includes some return ending gadgets in its output.
        :return: None, alters the JOPGadgets collection.
        """
        gadgetsToRemove = []
        for jopGadget in self.JOPGadgets:
            last_instr = jopGadget.instructions[len(jopGadget.instructions)-1]
            if last_instr.startswith("ret"):
                print("Filtering Gadget: " + str(jopGadget.instructions))
                gadgetsToRemove.append(jopGadget)

        for gadget in gadgetsToRemove:
            self.JOPGadgets.remove(gadget)

    def getCOPGadgets(self):
        """
        Reads through the recorded JOP gadgets and populates COP gadgets
        """
        for jopGadget in self.JOPGadgets:
            last_instr = jopGadget.instructions[len(jopGadget.instructions)-1]
            if last_instr.startswith("call"):
                self.COPGadgets.append(jopGadget)

    def parseClasses(self, output):
        """
        :param str output: Console output from the microgadget scanner
        :return:
        """

        lines = output.split("\n")
        for line in lines:
            if line.find("Classes Satisfied") != -1:
                return line[:line.find(" ")]

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
