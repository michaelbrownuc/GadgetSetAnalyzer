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

        # Initialize score
        self.score = 0.0

    def is_useless_op(self):
        """
        :return boolean: Returns True if the first instruction opcode is in the "useless" list, False otherwise
                         Default behavior is to consider opcodes useful unless otherwise observed.
        """
        first_opcode = self.instructions[0].opcode

        # Bulk catch for all "jump" opcodes: No reason to include the instruction, just use the suffix directly
        if first_opcode.startswith("j"):
            return True
        # Bulk catch for bounds checked jumps, same reason as above
        if first_opcode.startswith("bnd"):
            return True
        # Bulk catch for all "ret" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("ret"):
            return True
        # Bulk catch for all "iret" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("iret"):
            return True
        # Bulk catch for all "call" opcodes: Bug in ROP gadget finds some gadgets that start with this GPI
        if first_opcode.startswith("call"):
            return True

        # Useless opcodes:
        # NOP - No reason to include the instruction, just use the suffix directly
        # LJMP - Same reason as "jump" opcodes above
        useless = ["nop", "fnop", "ljmp"]
        return first_opcode in useless

    def contains_unusable_op(self):
        """
        :return boolean: Returns True if any instruction opcode is unusable.  False otherwise
                         unusable instructions are Ring-0 opcodes that trap in user mode and some other exceptional ops.
        """
        for instr in self.instructions:
            # Bulk catch for all "invalidate" opcodes: Ring-0 instructions
            if instr.opcode.startswith("inv"):
                return True
            # Bulk catch for all "Virtual-Machine" opcodes: Ring-0 instructions
            if instr.opcode.startswith("vm") and instr.opcode != "vminsd" and instr.opcode != "vminpd":
                return True
            # Bulk catch for all "undefined" opcodes
            if instr.opcode.startswith("ud"):
                return True

            # Other Ring-0 opcodes and RSM, LOCK prefix
            unusable = ["clts", "hlt", "lgdt", "lidt", "lldt", "lmsw", "ltr", "monitor", "mwait",
                        "swapgs", "sysexit", "sysreturn", "wbinvd", "wrmsr", "xsetbv", "rsm", "lock"]
            if instr.opcode in unusable:
                return True

            # Check for ring-0 operands (control, debug, and test registers)
            if instr.op1 is not None:
                if instr.op1.startswith("cr") or instr.op1.startswith("tr") or instr.op1.startswith("db"):
                    return True
            if instr.op2 is not None:
                if instr.op2.startswith("cr") or instr.op2.startswith("tr") or instr.op2.startswith("db"):
                    return True

        return False

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
        :return boolean: Returns True if the gadget is 'jmp' or 'call' ending and the call target is a constant offset
                         or does not target a recognized register family. False otherwise
        """
        last_instr = self.instructions[len(self.instructions)-1]
        if last_instr.opcode.startswith("call") or last_instr.opcode.startswith("jmp"):
            if Instruction.get_operand_register_family(last_instr.op1) is None:
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

    def clobbers_created_value(self):
        """
        :return boolean: Returns True if the gadget completely overwrites the value created in the first instruction,
                         False otherwise.
        """

        first_instr = self.instructions[0]

        # Check if the first instruction creates a value or is an xchg operand (excluded as an edge case)
        if not first_instr.creates_value() or "xchg" in first_instr.opcode:
            return False

        # Check op1 to find the register family to protect
        first_family = Instruction.get_operand_register_family(first_instr.op1)

        # Most likely means first operand is a constant, exclude from analysis
        if first_family is None:
            return False

        # Iterate through intermediate instructions, determine if it overwrites protected value (or part of it)
        for i in range(1, len(self.instructions)-1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value() or "xchg" in cur_instr.opcode:
                continue

            # Check for non-static modification of the register family
            if first_family == Instruction.get_operand_register_family(cur_instr.op1):
                if (cur_instr.op2 is None and cur_instr.opcode not in ["inc", "dec", "neg", "not"]) or \
                   (cur_instr.op2 is not None and not Instruction.is_constant(cur_instr.op2)):
                    return True

        return False

    def creates_unusable_value(self):
        """
        :return boolean: Returns True if the gadget creates a value in segment or extension registers, or are
                         RIP-relative, or are constant memory locations; False otherwise.
        """
        # Check if the first instruction creates a value (or may potentially set a flag
        first_instr = self.instructions[0]
        if first_instr.opcode in ["cmp", "test", "push"] or first_instr.op1 is None:
            return False

        # Check if first operand is not a constant and it does not belong to a recognized register family
        if not Instruction.is_constant(first_instr.op1) and \
           Instruction.get_operand_register_family(first_instr.op1) is None:
            return True

        return False


    def contains_intermediate_GPI(self):
        """
        :return boolean: Returns True if the gadget's intermediate instructions contain a GPI (or a generic interrupt),
                         False otherwise.
        """
        for i in range(len(self.instructions)-1):
            cur_opcode = self.instructions[i].opcode
            cur_target = self.instructions[i].op1
            if cur_opcode.startswith("ret") or \
               cur_opcode == "syscall" or cur_opcode == "sysenter" or cur_opcode.startswith("int") or \
               ("jmp" in cur_opcode and not Instruction.is_constant(cur_target)) or \
               ("call" in cur_opcode and not Instruction.is_constant(cur_target)):
                return True

        return False

    def clobbers_stack_pointer(self):
        """
        :return boolean: Returns True if the ROP gadget's instructions assign a non-static value to the stack pointer
                         register, False otherwise.
        """
        # Only check ROP gadgets
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("ret"):
            for i in range(len(self.instructions) - 1):
                cur_instr = self.instructions[i]

                # Ignore instructions that do not create values
                if not cur_instr.creates_value():
                    continue

                # Check for non-static modification of the stack pointer register family
                if Instruction.get_operand_register_family(cur_instr.op1) == 7:  # RSP, ESP family number
                    if (cur_instr.op2 is None and cur_instr.opcode not in ["inc", "dec", "pop"]) or \
                       (cur_instr.op2 is not None and not Instruction.is_constant(cur_instr.op2)):
                        return True
        return False

    def clobbers_indirect_target(self):
        """
        :return boolean: Returns True if the JOP/COP gadget's instructions modify the indirect branch register in
                         certain ways, False otherwise.
        """
        # Get the register family of the indirect jump / call
        last_instr = self.instructions[len(self.instructions)-1]
        if last_instr.opcode.startswith("jmp") or last_instr.opcode.startswith("call"):
            family = Instruction.get_operand_register_family(last_instr.op1)

            # Check each instruction to see if it clobbers the value
            for i in range(len(self.instructions)-1):
                cur_instr = self.instructions[i]

                # First check if the instruction modifies the target
                if cur_instr.op1 in Instruction.register_families[family]:
                    # Does the instruction zeroize out the target?
                    if cur_instr.opcode == "xor" and cur_instr.op1 == cur_instr.op2:
                        return True
                    # Does the instruction perform a RIP-relative LEA into the target?
                    if cur_instr.opcode == "lea" and ("rip" in cur_instr.op2 or "eip" in cur_instr.op2):
                        return True
                    # Does the instruction load a string or a value of an input port into the target?
                    if cur_instr.opcode.startswith("lods") or cur_instr.opcode == "in":
                        return True
                    # Does the instruction overwrite the target with a static value or segment register value?
                    if "mov" in cur_instr.opcode and (Instruction.is_constant(cur_instr.op2) or
                                                      Instruction.get_operand_register_family(cur_instr.op2) is None):
                        return True
        return False

    def has_invalid_int_handler(self):
        """
        :return boolean: Returns True if the gadget's instructions assign a non-static value to the stack pointer
                         register, False otherwise.
        """
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("int") and last_instr.op1 != "0x80":
            return True

        return False

    def is_rip_relative_indirect_branch(self):
        """
        :return boolean: Returns True if the gadget is a JOP/COP gadget relying on a RIP relative indirect branch,
                         False otherwise.
        """
        last_instr = self.instructions[len(self.instructions) - 1]
        if last_instr.opcode.startswith("jmp") or last_instr.opcode.startswith("call"):
            if "rip" in last_instr.op1 or "eip" in last_instr.op1:
                return True

        return False

    def contains_static_call(self):
        for i in range(1, len(self.instructions)-1):
            cur_instr = self.instructions[i]
            if cur_instr.opcode.startswith("call") and Instruction.is_constant(cur_instr.op1):
                return True

        return False

    def is_equal(self, rhs):
        """
        :return boolean: Returns True if the gadgets are an exact match, including offset. Used for gadget locality.
        """
        return self.offset == rhs.offset and self.instruction_string == rhs.instruction_string

    def is_duplicate(self, rhs):
        """
        :return boolean: Returns True if the gadgets are a semantic match. Used for non-locality gadget metrics.
                         Semantic match is defined as the exact same sequence of equivalent instructions.
        """
        if len(self.instructions) != len(rhs.instructions):
            return False

        for i in range(len(self.instructions)):
            if not self.instructions[i].is_equivalent(rhs.instructions[i]):
                return False

        return True

    def is_JOP_COP_dispatcher(self):
        """
        :return boolean: Returns True if the gadget is a JOP or COP dispatcher. Defined as a gadget that begins with a
                         arithmetic operation on a register and ends with a branch to a deference of that register. Used
                         to iterate through instructions in payload. Only restrictions on the arithmetic operation is
                         that it doesn't use the same register as both operands.
        """
        first_instr = self.instructions[0]
        last_instr = self.instructions[len(self.instructions) - 1]

        # Only consider gadgets that end in dereference of a register and start with opcodes of interest
        if "[" in last_instr.op1 and \
           first_instr.opcode in ["inc", "dec", "add", "adc", "sub", "sbb"] and "[" not in first_instr.op1:
            gpi_target = Instruction.get_operand_register_family(last_instr.op1)
            arith_target_1 = Instruction.get_operand_register_family(first_instr.op1)

            # Secondary check: if the second op is a constant ensure it is in range [1, 32]
            if Instruction.is_constant(first_instr.op2):
                additive_value = Instruction.get_operand_as_constant(first_instr.op2)
                if additive_value < 1 or additive_value > 32:
                    return False

            arith_target_2 = Instruction.get_operand_register_family(first_instr.op2)
            return gpi_target == arith_target_1 and arith_target_1 != arith_target_2

        return False

    def is_JOP_COP_dataloader(self):
        """
        :return boolean: Returns True if the gadget is a JOP or COP data loader. Defined as a gadget that begins with a
                         pop opcode to a non-memory location, that is also not the target of the GPI. Used to pop a
                         necessary value off stack en masse before redirecting to the dispatcher.
        """
        first_instr = self.instructions[0]

        if first_instr.opcode == "pop" and "[" not in first_instr.op1:
            gpi_target = Instruction.get_operand_register_family(self.instructions[len(self.instructions) - 1].op1)
            pop_target = Instruction.get_operand_register_family(first_instr.op1)
            return gpi_target != pop_target

        return False


    def is_JOP_initializer(self):
        """
        :return boolean: Returns True if the gadget is a JOP Initializer. Defined as a gadget that begins with a
                         "pop all" opcode, used to pop necessary values off stack en masse before redirecting to the
                         dispatcher.
        """
        return self.instructions[0].opcode.startswith("popa")

    def is_JOP_trampoline(self):
        """
        :return boolean: Returns True if the gadget is a JOP trampoline. Defined as a gadget that begins with a
                         pop opcode to a non-memory location, and that ends in a dereference of that value. Used to
                         redirect execution to value stored in memory.
        """
        first_instr = self.instructions[0]
        gpi_target_op = self.instructions[len(self.instructions) - 1].op1

        if first_instr.opcode == "pop" and "[" not in first_instr.op1:
            gpi_target = Instruction.get_operand_register_family(gpi_target_op)
            pop_target = Instruction.get_operand_register_family(first_instr.op1)
            return gpi_target == pop_target and "[" in gpi_target_op

        return False

    def is_COP_initializer(self):
        """
        :return boolean: Returns True if the gadget is a COP initializer. Defined as a gadget that begins with a
                         "pop all" opcode, does not use register bx/cx/dx/di as the call target, and does not clobber
                         bx/cx/dx or the call target in an intermediate instruction
        """
        first_instr = self.instructions[0]
        last_instr = self.instructions[len(self.instructions)-1]
        call_target = Instruction.get_operand_register_family(last_instr.op1)

        if first_instr.opcode.startswith("popa") and call_target not in [1, 2, 3, 5]:   # BX, CX, DX, DI families
            # Build collective list of register families to protect from being clobbered
            protected_families = [1, 2, 3, call_target]
            protected_registers = []
            for family in protected_families:
                for register in Instruction.register_families[family]:
                    protected_registers.append(register)

            # Scan intermediate instructions to ensure they do not clobber a protected register
            for i in range(1, len(self.instructions)-1):
                cur_instr = self.instructions[i]

                # Ignore instructions that do not create values
                if not cur_instr.creates_value():
                    continue

                # Check for non-static modification of the register family
                if cur_instr.op1 in protected_registers:
                    if (cur_instr.op2 is None and cur_instr.opcode not in ["inc", "dec", "neg", "not"]) or \
                       (cur_instr.op2 is not None and not Instruction.is_constant(cur_instr.op2)):
                        return False
            return True

        return False

    def is_COP_strong_trampoline(self):
        """
        :return boolean: Returns True if the gadget is a COP strong trampoline. Defined as a gadget that begins with a
                         pop opcode, and contains at least one other pop operation. The last non-pop all operation must
                         target the call target.
        """
        first_instr = self.instructions[0]
        last_instr = self.instructions[len(self.instructions) - 1]
        call_target = Instruction.get_operand_register_family(last_instr.op1)

        # Only consider instructions that start with a pop
        if first_instr.opcode == "pop" and "[" not in first_instr.op1:
            cnt_pops = 1
            last_pop_target = first_instr.op1

            # Scan intermediate instructions for pops
            for i in range(1, len(self.instructions)-1):
                cur_instr = self.instructions[i]

                if cur_instr.opcode.startswith("popa"):
                    cnt_pops += 1

                if cur_instr.opcode == "pop" and "[" not in cur_instr.op1:
                    cnt_pops += 1
                    last_pop_target = cur_instr.op1

            # Check that at least two pops occurred and the last pop target is the call target
            if cnt_pops > 1 and last_pop_target in Instruction.register_families[call_target]:
                return True

        return False

    def is_COP_intrastack_pivot(self):
        """
        :return boolean: Returns True if the gadget is a COP Intra-stack pivot gadget. Defined as a gadget that begins
                         with an additive operation on the stack pointer register. Used to move around in shellcode
                         during COP exploits. Only restriction on the arithmetic operation is that the second operand
                         is not a pointer.
        """
        first_instr = self.instructions[0]

        if first_instr.opcode in ["inc", "add", "adc", "sub", "sbb"] and "[" not in first_instr.op1:
            arith_target = Instruction.get_operand_register_family(first_instr.op1)
            if arith_target == 7:             # RSP, ESP family number
                if first_instr.op2 is None or "[" not in first_instr.op2:
                    return True

        return False

    def check_contains_leave(self):
        """
        :return void: Increases gadget's score if the gadget has an intermediate "leave" instruction.
        """
        for i in range(1, len(self.instructions)-1):
            if self.instructions[i].opcode == "leave":
                self.score += 2.0
                return    # Only penalize gadget once

    def check_sp_target_of_operation(self):
        """
        :return void: Increases gadget's score if the gadget has an intermediate instruction that performs certain
                      operations on the stack pointer register family.
        """
        # Scan instructions to determine if they modify the stack pointer register family
        for i in range(len(self.instructions)-1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value():
                continue

            # Increase score by 4 for move, load address, and exchange ops, 3 for shift/rotate ops, and 2 for others
            if Instruction.get_operand_register_family(cur_instr.op1) == 7:    # RSP, ESP family number
                if "xchg" in cur_instr.opcode or "mov" in cur_instr.opcode or cur_instr.opcode in ["lea"]:
                    self.score += 4.0
                elif cur_instr.opcode in ["shl", "shr", "sar", "sal", "ror", "rol", "rcr", "rcl"]:
                    self.score += 3.0
                elif cur_instr.opcode == "pop":
                    self.score += 1.0
                else:
                    self.score += 2.0   # Will be a static modification, otherwise it would have been rejected earlier

    def check_negative_sp_offsets(self):
        """
        :return void: Increases gadget's score if its cumulative register offsets are negative.
        """
        sp_offset = 0

        # Scan instructions to determine if they modify the stack pointer
        for i in range(len(self.instructions)):
            cur_instr = self.instructions[i]

            if cur_instr.opcode == "push":
                sp_offset -= 8

            elif cur_instr.opcode == "pop" and cur_instr.op1 not in Instruction.register_families[7]:
                sp_offset += 8

            elif cur_instr.opcode in ["add", "adc"] and cur_instr.op1 in Instruction.register_families[7] and \
               Instruction.is_constant(cur_instr.op2):
                sp_offset += Instruction.get_operand_as_constant(cur_instr.op2)

            elif cur_instr.opcode in ["sub", "sbb"] and cur_instr.op1 in Instruction.register_families[7] and \
               Instruction.is_constant(cur_instr.op2):
                sp_offset -= Instruction.get_operand_as_constant(cur_instr.op2)

            elif cur_instr.opcode == "inc" and cur_instr.op1 in Instruction.register_families[7]:
                sp_offset += 1

            elif cur_instr.opcode == "dec" and cur_instr.op1 in Instruction.register_families[7]:
                sp_offset -= 1

            elif cur_instr.opcode.startswith("ret") and cur_instr.op1 is not None:
                sp_offset += Instruction.get_operand_as_constant(cur_instr.op1)

        if sp_offset < 0:
            self.score += 2.0

    def check_contains_conditional_op(self):
        """
        :return void: Increases gadget's score if it contains conditional instructions like jumps, sets, and moves.
        """
        # Scan instructions to determine if they modify the stack pointer
        for i in range(len(self.instructions)-1):
            cur_instr = self.instructions[i]

            if cur_instr.opcode.startswith("j") and cur_instr.opcode != "jmp":
                self.score += 3.0
            elif "cmov" in cur_instr.opcode or "cmpxchg" in cur_instr.opcode:
                self.score += 2.0
            elif "set" in cur_instr.opcode:
                self.score += 1.0

    def check_register_ops(self):
        """
        :return void: Increases gadget's score if it contains operations on a value carrying or a bystander register
        """
        first_instr = self.instructions[0]

        # Check if the first instruction creates a value or is an xchg operand (excluded as an edge case)
        if not first_instr.creates_value() or "xchg" in first_instr.opcode:
            first_family = None
        else:
            # Check op1 to find the register family to protect
            first_family = Instruction.get_operand_register_family(first_instr.op1)

        for i in range(1, len(self.instructions)-1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value():
                continue

            # If the new value is a modification of the value-carrying register
            if first_family is not None and first_family == Instruction.get_operand_register_family(cur_instr.op1):
                if cur_instr.opcode in ["shl", "shr", "sar", "sal", "ror", "rol", "rcr", "rcl"]:
                    self.score += 1.5
                else:
                    self.score += 1.0  # Will be a static modification, otherwise it would have been rejected earlier
            elif "xchg" not in cur_instr.opcode and cur_instr.opcode != "pop":
                # The modification is to a "bystander register". static mods +0.5, non-static +1.0
                if cur_instr.op2 is not None and Instruction.get_operand_register_family(cur_instr.op2) is not None:
                    self.score += 1.0
                else:
                    self.score += 0.5

    def check_branch_target_of_operation(self):
        """
        :return void: Increases gadget's score if the gadget has an intermediate instruction that performs certain
                      operations on the indirect branch target register family.
        """
        last_instr = self.instructions[len(self.instructions)-1]
        target_family = Instruction.get_operand_register_family(last_instr.op1)

        # Scan instructions to determine if they modify the target register family
        for i in range(len(self.instructions) - 1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value():
                continue

            # Increase score by 3 for shift/rotate ops, and 2 for others
            if Instruction.get_operand_register_family(cur_instr.op1) == target_family:
                if cur_instr.opcode in ["shl", "shr", "sar", "sal", "ror", "rol", "rcr", "rcl"]:
                    self.score += 3.0
                else:    # All other modifications to target register
                    self.score += 2.0

    def check_memory_writes(self):
        """
        :return void: Increases gadget's score if the gadget has an instruction that writes to memory.
        """
        # Iterate through instructions except GPI
        for i in range(len(self.instructions)-1):
            cur_instr = self.instructions[i]

            # Ignore instructions that do not create values
            if not cur_instr.creates_value():
                continue

            # Have to check both operands for xchg instrucitons
            if "xchg" in cur_instr.opcode and ("[" in cur_instr.op1 or "[" in cur_instr.op2):
                self.score += 1.0
            elif cur_instr.op1 is not None and "[" in cur_instr.op1:
                self.score += 1.0
