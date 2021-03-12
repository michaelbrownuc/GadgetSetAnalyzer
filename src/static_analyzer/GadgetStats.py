"""
Gadget Stats class
"""

# Standard Library Imports

# Third Party Imports

# Local Imports
from static_analyzer.GadgetSet import GadgetSet
from static_analyzer.Gadget import Gadget


class GadgetStats(object):
    """
    The Gadget Stats class represents data resulting from the comparison of an original package's gadget set to the
    gadget set of its transformed variant.
    """

    def __init__(self, original, variant, output_console, output_locality):
        """
        GadgetStats constructor
        :param GadgetSet original: Gadget Set from the original package
        :param GadgetSet variant: Gadget Set from the variant package
        :param boolean output_console: Indicates whether or not to print info when computed
        :param boolean output_locality: Indicates whether or not to calculate gadget locality, which is CPU intensive
        """
        self.original = original
        self.variant = variant
        self.name = original.name + " <-> " + variant.name

        # Gadget Count Differences and Reduction Percentages
        self.ROPCountDiff = len(original.ROPGadgets) - len(variant.ROPGadgets)
        if len(original.ROPGadgets) > 0:
            self.ROPCountReduction = self.ROPCountDiff / len(original.ROPGadgets)
        else:
            self.ROPCountReduction = 0

        self.JOPCountDiff = len(original.JOPGadgets) - len(variant.JOPGadgets)
        if len(original.JOPGadgets) > 0:
            self.JOPCountReduction = self.JOPCountDiff / len(original.JOPGadgets)
        else:
            self.JOPCountReduction = 0

        self.COPCountDiff = len(original.COPGadgets) - len(variant.COPGadgets)
        if len(original.COPGadgets) > 0:
            self.COPCountReduction = self.COPCountDiff / len(original.COPGadgets)
        else:
            self.COPCountReduction = 0

        self.SysCountDiff = len(original.SyscallGadgets) - len(variant.SyscallGadgets)
        if len(original.SyscallGadgets) > 0:
            self.SysCountReduction = self.SysCountDiff / len(original.SyscallGadgets)
        else:
            self.SysCountReduction = 0

        self.JOPDispatchersCountDiff = len(original.JOPDispatchers) - len(variant.JOPDispatchers)
        if len(original.JOPDispatchers) > 0:
            self.JOPDispatchersCountReduction = self.JOPDispatchersCountDiff / len(original.JOPDispatchers)
        else:
            self.JOPDispatchersCountReduction = 0

        self.JOPDataLoadersCountDiff = len(original.JOPDataLoaders) - len(variant.JOPDataLoaders)
        if len(original.JOPDataLoaders) > 0:
            self.JOPDataLoadersCountReduction = self.JOPDataLoadersCountDiff / len(original.JOPDataLoaders)
        else:
            self.JOPDataLoadersCountReduction = 0

        self.JOPInitializersCountDiff = len(original.JOPInitializers) - len(variant.JOPInitializers)
        if len(original.JOPInitializers) > 0:
            self.JOPInitializersCountReduction = self.JOPInitializersCountDiff / len(original.JOPInitializers)
        else:
            self.JOPInitializersCountReduction = 0

        self.JOPTrampolinesCountDiff = len(original.JOPTrampolines) - len(variant.JOPTrampolines)
        if len(original.JOPTrampolines) > 0:
            self.JOPTrampolinesCountReduction = self.JOPTrampolinesCountDiff / len(original.JOPTrampolines)
        else:
            self.JOPTrampolinesCountReduction = 0

        self.COPDispatchersCountDiff = len(original.COPDispatchers) - len(variant.COPDispatchers)
        if len(original.COPDispatchers) > 0:
            self.COPDispatchersCountReduction = self.COPDispatchersCountDiff / len(original.COPDispatchers)
        else:
            self.COPDispatchersCountReduction = 0

        self.COPDataLoadersCountDiff = len(original.COPDataLoaders) - len(variant.COPDataLoaders)
        if len(original.COPDataLoaders) > 0:
            self.COPDataLoadersCountReduction = self.COPDataLoadersCountDiff / len(original.COPDataLoaders)
        else:
            self.COPDataLoadersCountReduction = 0

        self.COPInitializersCountDiff = len(original.COPInitializers) - len(variant.COPInitializers)
        if len(original.COPInitializers) > 0:
            self.COPInitializersCountReduction = self.COPInitializersCountDiff / len(original.COPInitializers)
        else:
            self.COPInitializersCountReduction = 0

        self.COPStrongTrampolinesCountDiff = len(original.COPStrongTrampolines) - len(variant.COPStrongTrampolines)
        if len(original.COPStrongTrampolines) > 0:
            self.COPStrongTrampolinesCountReduction = self.COPStrongTrampolinesCountDiff / len(original.COPStrongTrampolines)
        else:
            self.COPStrongTrampolinesCountReduction = 0

        self.COPIntrastackPivotsCountDiff = len(original.COPIntrastackPivots) - len(variant.COPIntrastackPivots)
        if len(original.COPIntrastackPivots) > 0:
            self.COPIntrastackPivotsCountReduction = self.COPIntrastackPivotsCountDiff / len(original.COPIntrastackPivots)
        else:
            self.COPIntrastackPivotsCountReduction = 0

        # Gadget Introduction Counts and Percentages by type
        originalROPSet = GadgetStats.get_gadget_set(original.ROPGadgets)
        variantROPSet = GadgetStats.get_gadget_set(variant.ROPGadgets)
        commonROPSet = originalROPSet & variantROPSet
        ROPIntroducedSet = variantROPSet - commonROPSet
        if len(variantROPSet) > 0:
            self.ROPIntroductionRate = len(ROPIntroducedSet) / len(variantROPSet)
        else:
            self.ROPIntroductionRate = 0

        originalJOPSet = GadgetStats.get_gadget_set(original.JOPGadgets)
        variantJOPSet = GadgetStats.get_gadget_set(variant.JOPGadgets)
        commonJOPSet = originalJOPSet & variantJOPSet
        JOPIntroducedSet = variantJOPSet - commonJOPSet
        if len(variantJOPSet) > 0:
            self.JOPIntroductionRate = len(JOPIntroducedSet) / len(variantJOPSet)
        else:
            self.JOPIntroductionRate = 0

        originalCOPSet = GadgetStats.get_gadget_set(original.COPGadgets)
        variantCOPSet = GadgetStats.get_gadget_set(variant.COPGadgets)
        commonCOPSet = originalCOPSet & variantCOPSet
        COPIntroducedSet = variantCOPSet - commonCOPSet
        if len(variantCOPSet) > 0:
            self.COPIntroductionRate = len(COPIntroducedSet) / len(variantCOPSet)
        else:
            self.COPIntroductionRate = 0

        originalSysSet = GadgetStats.get_gadget_set(original.SyscallGadgets)
        variantSysSet = GadgetStats.get_gadget_set(variant.SyscallGadgets)
        commonSysSet = originalSysSet & variantSysSet
        sysIntroducedSet = variantSysSet - commonSysSet
        if len(variantSysSet) > 0:
            self.SysIntroductionRate = len(sysIntroducedSet) / len(variantSysSet)
        else:
            self.SysIntroductionRate = 0

        originalJOPDispatchersSet = GadgetStats.get_gadget_set(original.JOPDispatchers)
        variantJOPDispatchersSet = GadgetStats.get_gadget_set(variant.JOPDispatchers)
        commonJOPDispatchersSet = originalJOPDispatchersSet & variantJOPDispatchersSet
        JOPDispatchersIntroducedSet = variantJOPDispatchersSet - commonJOPDispatchersSet
        if len(variantJOPDispatchersSet) > 0:
            self.JOPDispatchersIntroductionRate = len(JOPDispatchersIntroducedSet) / len(variantJOPDispatchersSet)
        else:
            self.JOPDispatchersIntroductionRate = 0

        originalJOPDataLoadersSet = GadgetStats.get_gadget_set(original.JOPDataLoaders)
        variantJOPDataLoadersSet = GadgetStats.get_gadget_set(variant.JOPDataLoaders)
        commonJOPDataLoadersSet = originalJOPDataLoadersSet & variantJOPDataLoadersSet
        JOPDataLoadersIntroducedSet = variantJOPDataLoadersSet - commonJOPDataLoadersSet
        if len(variantJOPDataLoadersSet) > 0:
            self.JOPDataLoadersIntroductionRate = len(JOPDataLoadersIntroducedSet) / len(variantJOPDataLoadersSet)
        else:
            self.JOPDataLoadersIntroductionRate = 0

        originalJOPInitializersSet = GadgetStats.get_gadget_set(original.JOPInitializers)
        variantJOPInitializersSet = GadgetStats.get_gadget_set(variant.JOPInitializers)
        commonJOPInitializersSet = originalJOPInitializersSet & variantJOPInitializersSet
        JOPInitializersIntroducedSet = variantJOPInitializersSet - commonJOPInitializersSet
        if len(variantJOPInitializersSet) > 0:
            self.JOPInitializersIntroductionRate = len(JOPInitializersIntroducedSet) / len(variantJOPInitializersSet)
        else:
            self.JOPInitializersIntroductionRate = 0

        originalJOPTrampolinesSet = GadgetStats.get_gadget_set(original.JOPTrampolines)
        variantJOPTrampolinesSet = GadgetStats.get_gadget_set(variant.JOPTrampolines)
        commonJOPTrampolinesSet = originalJOPTrampolinesSet & variantJOPTrampolinesSet
        JOPTrampolinesIntroducedSet = variantJOPTrampolinesSet - commonJOPTrampolinesSet
        if len(variantJOPTrampolinesSet) > 0:
            self.JOPTrampolinesIntroductionRate = len(JOPTrampolinesIntroducedSet) / len(variantJOPTrampolinesSet)
        else:
            self.JOPTrampolinesIntroductionRate = 0

        originalCOPDispatchersSet = GadgetStats.get_gadget_set(original.COPDispatchers)
        variantCOPDispatchersSet = GadgetStats.get_gadget_set(variant.COPDispatchers)
        commonCOPDispatchersSet = originalCOPDispatchersSet & variantCOPDispatchersSet
        COPDispatchersIntroducedSet = variantCOPDispatchersSet - commonCOPDispatchersSet
        if len(variantCOPDispatchersSet) > 0:
            self.COPDispatchersIntroductionRate = len(COPDispatchersIntroducedSet) / len(variantCOPDispatchersSet)
        else:
            self.COPDispatchersIntroductionRate = 0

        originalCOPDataLoadersSet = GadgetStats.get_gadget_set(original.COPDataLoaders)
        variantCOPDataLoadersSet = GadgetStats.get_gadget_set(variant.COPDataLoaders)
        commonCOPDataLoadersSet = originalCOPDataLoadersSet & variantCOPDataLoadersSet
        COPDataLoadersIntroducedSet = variantCOPDataLoadersSet - commonCOPDataLoadersSet
        if len(variantCOPDataLoadersSet) > 0:
            self.COPDataLoadersIntroductionRate = len(COPDataLoadersIntroducedSet) / len(variantCOPDataLoadersSet)
        else:
            self.COPDataLoadersIntroductionRate = 0

        originalCOPInitializersSet = GadgetStats.get_gadget_set(original.COPInitializers)
        variantCOPInitializersSet = GadgetStats.get_gadget_set(variant.COPInitializers)
        commonCOPInitializersSet = originalCOPInitializersSet & variantCOPInitializersSet
        COPInitializersIntroducedSet = variantCOPInitializersSet - commonCOPInitializersSet
        if len(variantCOPInitializersSet) > 0:
            self.COPInitializersIntroductionRate = len(COPInitializersIntroducedSet) / len(variantCOPInitializersSet)
        else:
            self.COPInitializersIntroductionRate = 0

        originalCOPStrongTrampolinesSet = GadgetStats.get_gadget_set(original.COPStrongTrampolines)
        variantCOPStrongTrampolinesSet = GadgetStats.get_gadget_set(variant.COPStrongTrampolines)
        commonCOPStrongTrampolinesSet = originalCOPStrongTrampolinesSet & variantCOPStrongTrampolinesSet
        COPStrongTrampolinesIntroducedSet = variantCOPStrongTrampolinesSet - commonCOPStrongTrampolinesSet
        if len(variantCOPStrongTrampolinesSet) > 0:
            self.COPStrongTrampolinesIntroductionRate = len(COPStrongTrampolinesIntroducedSet) / len(variantCOPStrongTrampolinesSet)
        else:
            self.COPStrongTrampolinesIntroductionRate = 0

        originalCOPIntrastackPivotsSet = GadgetStats.get_gadget_set(original.COPIntrastackPivots)
        variantCOPIntrastackPivotsSet = GadgetStats.get_gadget_set(variant.COPIntrastackPivots)
        commonCOPIntrastackPivotsSet = originalCOPIntrastackPivotsSet & variantCOPIntrastackPivotsSet
        COPIntrastackPivotsIntroducedSet = variantCOPIntrastackPivotsSet - commonCOPIntrastackPivotsSet
        if len(variantCOPIntrastackPivotsSet) > 0:
            self.COPIntrastackPivotsIntroductionRate = len(COPIntrastackPivotsIntroducedSet) / len(variantCOPIntrastackPivotsSet)
        else:
            self.COPIntrastackPivotsIntroductionRate = 0

        # Total Set
        orig_total_set = originalROPSet | originalJOPSet | originalCOPSet | originalSysSet | \
                         originalJOPInitializersSet | originalJOPDispatchersSet | originalJOPDataLoadersSet | \
                         originalJOPTrampolinesSet | originalCOPStrongTrampolinesSet | originalCOPDataLoadersSet | \
                         originalCOPInitializersSet | originalCOPDispatchersSet | originalCOPIntrastackPivotsSet
        variant_total_set = variantROPSet | variantJOPSet | variantCOPSet | variantSysSet | \
                            variantJOPInitializersSet | variantJOPDispatchersSet | variantJOPDataLoadersSet | \
                            variantJOPTrampolinesSet | variantCOPStrongTrampolinesSet | variantCOPDataLoadersSet | \
                            variantCOPInitializersSet | variantCOPDispatchersSet | variantCOPIntrastackPivotsSet

        self.totalUniqueCountDiff = len(orig_total_set) - len(variant_total_set)
        if len(orig_total_set) > 0:
            self.totalUniqueCountReduction = self.totalUniqueCountDiff / len(orig_total_set)
        else:
            self.totalUniqueCountReduction = 0

        self.total_sp_count_diff = original.total_sp_gadgets - variant.total_sp_gadgets
        if original.total_sp_gadgets > 0:
            self.total_sp_reduction = self.total_sp_count_diff / original.total_sp_gadgets
        else:
            self.total_sp_reduction = 0

        total_common_set = orig_total_set & variant_total_set       
        total_introduced_set = variant_total_set - total_common_set
        if len(variant_total_set) > 0:
            self.totalUniqueIntroductionRate = len(total_introduced_set) / len(variant_total_set)
        else:
            self.totalUniqueIntroductionRate = 0

        self.total_sp_type_reduction = original.total_sp_types - variant.total_sp_types

        # Satisfied classes count differences
        self.practical_ROP_exp_diff = original.practical_ROP_expressivity - variant.practical_ROP_expressivity
        self.practical_ASLR_ROP_exp_diff = original.practical_ASLR_ROP_expressivity - variant.practical_ASLR_ROP_expressivity
        self.turing_complete_ROP_exp_diff = original.turing_complete_ROP_expressivity - variant.turing_complete_ROP_expressivity

        # Calculate gadget locality
        if output_locality:
            local_gadgets = GadgetStats.findEqualGadgets(original.allGadgets, variant.allGadgets)
            self.gadgetLocality = local_gadgets / len(variant.allGadgets)
        else:
            self.gadgetLocality = 0.0

        # Calculate gadget quality
        self.keptQualityROPCountDiff = len(original.ROPGadgets) - len(variant.ROPGadgets)
        self.keptQualityJOPCountDiff = len(original.JOPGadgets) - len(variant.JOPGadgets)
        self.keptQualityCOPCountDiff = len(original.COPGadgets) - len(variant.COPGadgets)
        self.total_functional_count_diff = original.total_functional_gadgets - variant.total_functional_gadgets

        self.averageROPQualityDiff = original.averageROPQuality - variant.averageROPQuality
        self.averageJOPQualityDiff = original.averageJOPQuality - variant.averageJOPQuality
        self.averageCOPQualityDiff = original.averageCOPQuality - variant.averageCOPQuality
        self.total_average_quality_diff = original.average_functional_quality - variant.average_functional_quality

        if output_console:
            self.printStats(output_locality)

    def printStats(self, output_locality):
        rate_format = "{:.1%}"
        print("======================================================================")
        print("Gadget Stats for " + self.name)
        print("======================================================================")
        print("Total Unique Gadgets:")
        print("Count Difference: "  + str(self.totalUniqueCountDiff))
        print("Reduction Rate: "    + rate_format.format(self.totalUniqueCountReduction))
        print("Introduction Rate: " + rate_format.format(self.totalUniqueIntroductionRate))
        print("======================================================================")
        print("ROP Gadgets:")
        print("Count Difference: " + str(self.ROPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.ROPCountReduction))
        print("Introduction Rate: " + rate_format.format(self.ROPIntroductionRate))
        print("======================================================================")
        print("JOP Gadgets:")
        print("Count Difference: " + str(self.JOPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPCountReduction))
        print("Introduction Rate: " + rate_format.format(self.JOPIntroductionRate))
        print("======================================================================")
        print("COP Gadgets:")
        print("Count Difference: " + str(self.COPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPIntroductionRate))
        print("======================================================================")
        print("Syscall Gadgets:")
        print("Count Difference: " + str(self.SysCountDiff))
        print("Reduction Rate: " + rate_format.format(self.SysCountReduction))
        print("Introduction Rate: " + rate_format.format(self.SysIntroductionRate))
        print("======================================================================")
        print("JOP Dispatcher Gadgets:")
        print("Count Difference: " + str(self.JOPDispatchersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPDispatchersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.JOPDispatchersIntroductionRate))
        print("======================================================================")
        print("JOP Data Loader Gadgets:")
        print("Count Difference: " + str(self.JOPDataLoadersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPDataLoadersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.JOPDataLoadersIntroductionRate))
        print("======================================================================")
        print("JOP Initializer Gadgets:")
        print("Count Difference: " + str(self.JOPInitializersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPInitializersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.JOPInitializersIntroductionRate))
        print("======================================================================")
        print("JOP Trampoline Gadgets:")
        print("Count Difference: " + str(self.JOPTrampolinesCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPTrampolinesCountReduction))
        print("Introduction Rate: " + rate_format.format(self.JOPTrampolinesIntroductionRate))
        print("======================================================================")
        print("COP Dispatcher Gadgets:")
        print("Count Difference: " + str(self.COPDispatchersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPDispatchersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPDispatchersIntroductionRate))
        print("======================================================================")
        print("COP Data Loader Gadgets:")
        print("Count Difference: " + str(self.COPDataLoadersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPDataLoadersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPDataLoadersIntroductionRate))
        print("======================================================================")
        print("COP Initializer Gadgets:")
        print("Count Difference: " + str(self.COPInitializersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPInitializersCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPInitializersIntroductionRate))
        print("======================================================================")
        print("COP Strong Trampoline Gadgets:")
        print("Count Difference: " + str(self.COPStrongTrampolinesCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPStrongTrampolinesCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPStrongTrampolinesIntroductionRate))
        print("======================================================================")
        print("COP Intrastack Pivot Gadgets:")
        print("Count Difference: " + str(self.COPIntrastackPivotsCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPIntrastackPivotsCountReduction))
        print("Introduction Rate: " + rate_format.format(self.COPIntrastackPivotsIntroductionRate))
        print("======================================================================")
        print("ROP Gadget Quality:")
        print("ROP Count Difference: " + str(self.keptQualityROPCountDiff))
        print("ROP Average Quality Difference: " + str(self.averageROPQualityDiff))
        print("JOP Gadget Quality:")
        print("JOP Count Difference: " + str(self.keptQualityJOPCountDiff))
        print("JOP Average Quality Difference: " + str(self.averageJOPQualityDiff))
        print("COP Gadget Quality:")
        print("COP Count Difference: " + str(self.keptQualityCOPCountDiff))
        print("COP Average Quality Difference: " + str(self.averageCOPQualityDiff))
        print("======================================================================")
        print("ROP Expressivity:")
        print("Practical ROP Exploit Difference: " + str(self.practical_ROP_exp_diff))
        print("Practical ASLR-Proof ROP Exploit Difference: " + str(self.practical_ASLR_ROP_exp_diff))
        print("Simple Turing Complete ROP Exploit Difference: " + str(self.turing_complete_ROP_exp_diff))
        print("======================================================================")
        if output_locality:
            print("Gadget Locality for all gadgets: " + rate_format.format(self.gadgetLocality))


    @staticmethod
    def findEqualGadgets(original_set, variant_set):
        equal_cnt = 0
        for originalGadget in original_set:
            for variantGadget in variant_set:
                if originalGadget.is_equal(variantGadget):
                    equal_cnt += 1
        return equal_cnt

    @staticmethod
    def get_gadget_set(gadget_list):
        """
        Static method for generating a set of gadget strings suitable for performing set operations.
        :param Gadget[] gadget_list: A list of Gadget objects
        :return: A set of gadget strings suitable for performing set arithmetic
        """
        gadget_set = set()

        for gadget in gadget_list:
            gadget_set.add(gadget.instruction_string)

        return gadget_set

