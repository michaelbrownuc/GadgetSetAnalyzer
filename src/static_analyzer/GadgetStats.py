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
    gadget set of its debloated variant.
    """

    def __init__(self, original, variant):
        """
        GadgetStats constructor
        :param GadgetSet original: Gadget Set from the original package
        :param GadgetSet variant: Gadget Set from the variant package
        """
        self.original = original
        self.variant = variant
        self.name = original.name + " <-> " + variant.name

        # Gadget Count Differences and Reduction Percentages
        self.totalUniqueCountDiff = len(original.totalUniqueGadgets) - len(variant.totalUniqueGadgets)
        if len(original.totalUniqueGadgets) > 0:
            self.totalUniqueCountReduction = self.totalUniqueCountDiff / len(original.totalUniqueGadgets)
        else:
            self.totalUniqueCountReduction = 0

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

        self.SysCountDiff = len(original.SysGadgets) - len(variant.SysGadgets)
        if len(original.SysGadgets) > 0:
            self.SysCountReduction = self.SysCountDiff / len(original.SysGadgets)
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

        # Gadget Introduction Counts and Percentages
        commonSet = original.totalUniqueGadgets & variant.totalUniqueGadgets
        self.totalUniqueIntroducedSet = variant.totalUniqueGadgets - commonSet
        self.totalUniqueIntroductionRate = len(self.totalUniqueIntroducedSet) / len(variant.totalUniqueGadgets)

        originalROPSet = GadgetSet.getGadgetTypeSet(original.ROPGadgets)
        variantROPSet = GadgetSet.getGadgetTypeSet(variant.ROPGadgets)
        commonROPSet = originalROPSet & variantROPSet
        self.ROPIntroducedSet = variantROPSet - commonROPSet
        if len(variantROPSet) > 0:
            self.ROPIntroductionRate = len(self.ROPIntroducedSet) / len(variantROPSet)
        else:
            self.ROPIntroductionRate = 0

        originalJOPSet = GadgetSet.getGadgetTypeSet(original.JOPGadgets)
        variantJOPSet = GadgetSet.getGadgetTypeSet(variant.JOPGadgets)
        commonJOPSet = originalJOPSet & variantJOPSet
        self.JOPIntroducedSet = variantJOPSet - commonJOPSet
        if len(variantJOPSet) > 0:
            self.JOPIntroductionRate = len(self.JOPIntroducedSet) / len(variantJOPSet)
        else:
            self.JOPIntroductionRate = 0

        originalCOPSet = GadgetSet.getGadgetTypeSet(original.COPGadgets)
        variantCOPSet = GadgetSet.getGadgetTypeSet(variant.COPGadgets)
        commonCOPSet = originalCOPSet & variantCOPSet
        self.COPIntroducedSet = variantCOPSet - commonCOPSet
        if len(variantCOPSet) > 0:
            self.COPIntroductionRate = len(self.COPIntroducedSet) / len(variantCOPSet)
        else:
            self.COPIntroductionRate = 0

        originalSysSet = GadgetSet.getGadgetTypeSet(original.SysGadgets)
        variantSysSet = GadgetSet.getGadgetTypeSet(variant.SysGadgets)
        commonSysSet = originalSysSet & variantSysSet
        self.SysIntroducedSet = variantSysSet - commonSysSet
        if len(variantSysSet) > 0:
            self.SysIntroductionRate = len(self.SysIntroducedSet) / len(variantSysSet)
        else:
            self.SysIntroductionRate = 0
        self.SysIntroducedGadgets = variant.getGadgetsFromStrings(self.SysIntroducedSet, "SYS")

        originalJOPDispatchersSet = GadgetSet.getGadgetTypeSet(original.JOPDispatchers)
        variantJOPDispatchersSet = GadgetSet.getGadgetTypeSet(variant.JOPDispatchers)
        commonJOPDispatchersSet = originalJOPDispatchersSet & variantJOPDispatchersSet
        self.JOPDispatchersIntroducedSet = variantJOPDispatchersSet - commonJOPDispatchersSet
        if len(variantJOPDispatchersSet) > 0:
            self.JOPDispatchersIntroductionRate = len(self.JOPDispatchersIntroducedSet) / len(variantJOPDispatchersSet)
        else:
            self.JOPDispatchersIntroductionRate = 0
        self.JOPDispatchersIntroducedGadgets = variant.getGadgetsFromStrings(self.JOPDispatchersIntroducedSet, "JOP")

        originalJOPDataLoadersSet = GadgetSet.getGadgetTypeSet(original.JOPDataLoaders)
        variantJOPDataLoadersSet = GadgetSet.getGadgetTypeSet(variant.JOPDataLoaders)
        commonJOPDataLoadersSet = originalJOPDataLoadersSet & variantJOPDataLoadersSet
        self.JOPDataLoadersIntroducedSet = variantJOPDataLoadersSet - commonJOPDataLoadersSet
        if len(variantJOPDataLoadersSet) > 0:
            self.JOPDataLoadersIntroductionRate = len(self.JOPDataLoadersIntroducedSet) / len(variantJOPDataLoadersSet)
        else:
            self.JOPDataLoadersIntroductionRate = 0
        self.JOPDataLoadersIntroducedGadgets = variant.getGadgetsFromStrings(self.JOPDataLoadersIntroducedSet, "JOP")

        originalJOPInitializersSet = GadgetSet.getGadgetTypeSet(original.JOPInitializers)
        variantJOPInitializersSet = GadgetSet.getGadgetTypeSet(variant.JOPInitializers)
        commonJOPInitializersSet = originalJOPInitializersSet & variantJOPInitializersSet
        self.JOPInitializersIntroducedSet = variantJOPInitializersSet - commonJOPInitializersSet
        if len(variantJOPInitializersSet) > 0:
            self.JOPInitializersIntroductionRate = len(self.JOPInitializersIntroducedSet) / len(variantJOPInitializersSet)
        else:
            self.JOPInitializersIntroductionRate = 0
        self.JOPInitializersIntroducedGadgets = variant.getGadgetsFromStrings(self.JOPInitializersIntroducedSet, "JOP")

        originalJOPTrampolinesSet = GadgetSet.getGadgetTypeSet(original.JOPTrampolines)
        variantJOPTrampolinesSet = GadgetSet.getGadgetTypeSet(variant.JOPTrampolines)
        commonJOPTrampolinesSet = originalJOPTrampolinesSet & variantJOPTrampolinesSet
        self.JOPTrampolinesIntroducedSet = variantJOPTrampolinesSet - commonJOPTrampolinesSet
        if len(variantJOPTrampolinesSet) > 0:
            self.JOPTrampolinesIntroductionRate = len(self.JOPTrampolinesIntroducedSet) / len(variantJOPTrampolinesSet)
        else:
            self.JOPTrampolinesIntroductionRate = 0
        self.JOPTrampolinesIntroducedGadgets = variant.getGadgetsFromStrings(self.JOPTrampolinesIntroducedSet, "JOP")

        originalCOPDispatchersSet = GadgetSet.getGadgetTypeSet(original.COPDispatchers)
        variantCOPDispatchersSet = GadgetSet.getGadgetTypeSet(variant.COPDispatchers)
        commonCOPDispatchersSet = originalCOPDispatchersSet & variantCOPDispatchersSet
        self.COPDispatchersIntroducedSet = variantCOPDispatchersSet - commonCOPDispatchersSet
        if len(variantCOPDispatchersSet) > 0:
            self.COPDispatchersIntroductionRate = len(self.COPDispatchersIntroducedSet) / len(variantCOPDispatchersSet)
        else:
            self.COPDispatchersIntroductionRate = 0
        self.COPDispatchersIntroducedGadgets = variant.getGadgetsFromStrings(self.COPDispatchersIntroducedSet, "COP")

        originalCOPDataLoadersSet = GadgetSet.getGadgetTypeSet(original.COPDataLoaders)
        variantCOPDataLoadersSet = GadgetSet.getGadgetTypeSet(variant.COPDataLoaders)
        commonCOPDataLoadersSet = originalCOPDataLoadersSet & variantCOPDataLoadersSet
        self.COPDataLoadersIntroducedSet = variantCOPDataLoadersSet - commonCOPDataLoadersSet
        if len(variantCOPDataLoadersSet) > 0:
            self.COPDataLoadersIntroductionRate = len(self.COPDataLoadersIntroducedSet) / len(variantCOPDataLoadersSet)
        else:
            self.COPDataLoadersIntroductionRate = 0
        self.COPDataLoadersIntroducedGadgets = variant.getGadgetsFromStrings(self.COPDataLoadersIntroducedSet, "COP")

        originalCOPInitializersSet = GadgetSet.getGadgetTypeSet(original.COPInitializers)
        variantCOPInitializersSet = GadgetSet.getGadgetTypeSet(variant.COPInitializers)
        commonCOPInitializersSet = originalCOPInitializersSet & variantCOPInitializersSet
        self.COPInitializersIntroducedSet = variantCOPInitializersSet - commonCOPInitializersSet
        if len(variantCOPInitializersSet) > 0:
            self.COPInitializersIntroductionRate = len(self.COPInitializersIntroducedSet) / len(variantCOPInitializersSet)
        else:
            self.COPInitializersIntroductionRate = 0
        self.COPInitializersIntroducedGadgets = variant.getGadgetsFromStrings(self.COPInitializersIntroducedSet, "COP")

        originalCOPStrongTrampolinesSet = GadgetSet.getGadgetTypeSet(original.COPStrongTrampolines)
        variantCOPStrongTrampolinesSet = GadgetSet.getGadgetTypeSet(variant.COPStrongTrampolines)
        commonCOPStrongTrampolinesSet = originalCOPStrongTrampolinesSet & variantCOPStrongTrampolinesSet
        self.COPStrongTrampolinesIntroducedSet = variantCOPStrongTrampolinesSet - commonCOPStrongTrampolinesSet
        if len(variantCOPStrongTrampolinesSet) > 0:
            self.COPStrongTrampolinesIntroductionRate = len(self.COPStrongTrampolinesIntroducedSet) / len(variantCOPStrongTrampolinesSet)
        else:
            self.COPStrongTrampolinesIntroductionRate = 0
        self.COPStrongTrampolinesIntroducedGadgets = variant.getGadgetsFromStrings(self.COPStrongTrampolinesIntroducedSet, "COP")

        originalCOPIntrastackPivotsSet = GadgetSet.getGadgetTypeSet(original.COPIntrastackPivots)
        variantCOPIntrastackPivotsSet = GadgetSet.getGadgetTypeSet(variant.COPIntrastackPivots)
        commonCOPIntrastackPivotsSet = originalCOPIntrastackPivotsSet & variantCOPIntrastackPivotsSet
        self.COPIntrastackPivotsIntroducedSet = variantCOPIntrastackPivotsSet - commonCOPIntrastackPivotsSet
        if len(variantCOPIntrastackPivotsSet) > 0:
            self.COPIntrastackPivotsIntroductionRate = len(self.COPIntrastackPivotsIntroducedSet) / len(variantCOPIntrastackPivotsSet)
        else:
            self.COPIntrastackPivotsIntroductionRate = 0
        self.COPIntrastackPivotsIntroducedGadgets = variant.getGadgetsFromStrings(self.COPIntrastackPivotsIntroducedSet, "COP")

        # Satisfied classes count differences
        self.simpleTuringCompleteCountDiff = int(original.simpleTuringCompleteClasses) - \
                                             int(variant.simpleTuringCompleteClasses)

        # Calculate gadget locality
        self.localGadgets = GadgetStats.findEqualGadgets(original.ROPGadgets, variant.ROPGadgets) +\
                        GadgetStats.findEqualGadgets(original.JOPGadgets, variant.JOPGadgets) +\
                        GadgetStats.findEqualGadgets(original.SysGadgets, variant.SysGadgets)
        totalGadgets = len(variant.ROPGadgets) + len(variant.JOPGadgets) + len(variant.SysGadgets)
        self.gadgetLocality = self.localGadgets / totalGadgets

	# Calculate gadget quality
        self.keptQualityROPCountDiff = original.keptQualityROPGadgets - variant.keptQualityROPGadgets
        self.keptQualityJOPCountDiff = original.keptQualityJOPGadgets - variant.keptQualityJOPGadgets
        self.keptQualityCOPCountDiff = original.keptQualityCOPGadgets - variant.keptQualityCOPGadgets

        self.averageROPQualityDiff = original.averageROPQuality - variant.averageROPQuality
        self.averageJOPQualityDiff = original.averageJOPQuality - variant.averageJOPQuality
        self.averageCOPQualityDiff = original.averageCOPQuality - variant.averageCOPQuality

        #self.printStats()

    def printStats(self):
        rate_format = "{:.1%}"
        print("======================================================================")
        print("Gadget Stats for " + self.name)
        print("======================================================================")
        print("Total Unique Gadgets:")
        print("Count Difference: "  + str(self.totalUniqueCountDiff))
        print("Reduction Rate: "    + rate_format.format(self.totalUniqueCountReduction))
        print("Introduced Count: "  + str(len(self.totalUniqueIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.totalUniqueIntroductionRate))
        print("======================================================================")
        print("ROP Gadgets:")
        print("Count Difference: " + str(self.ROPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.ROPCountReduction))
        print("Introduced Count: " + str(len(self.ROPIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.ROPIntroductionRate))
        print("======================================================================")
        print("JOP Gadgets:")
        print("Count Difference: " + str(self.JOPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPCountReduction))
        print("Introduced Count: " + str(len(self.JOPIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.JOPIntroductionRate))
        print("======================================================================")
        print("COP Gadgets:")
        print("Count Difference: " + str(self.COPCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPCountReduction))
        print("Introduced Count: " + str(len(self.COPIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.COPIntroductionRate))
        print("======================================================================")
        print("Syscall Gadgets:")
        print("Count Difference: " + str(self.SysCountDiff))
        print("Reduction Rate: " + rate_format.format(self.SysCountReduction))
        print("Introduced Count: " + str(len(self.SysIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.SysIntroductionRate))
        print("======================================================================")
        print("JOP Dispatcher Gadgets:")
        print("Count Difference: " + str(self.JOPDispatchersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPDispatchersCountReduction))
        print("Introduced Count: " + str(len(self.JOPDispatchersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.JOPDispatchersIntroductionRate))
        print("======================================================================")
        print("JOP Data Loader Gadgets:")
        print("Count Difference: " + str(self.JOPDataLoadersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPDataLoadersCountReduction))
        print("Introduced Count: " + str(len(self.JOPDataLoadersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.JOPDataLoadersIntroductionRate))
        print("======================================================================")
        print("JOP Initializer Gadgets:")
        print("Count Difference: " + str(self.JOPInitializersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPInitializersCountReduction))
        print("Introduced Count: " + str(len(self.JOPInitializersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.JOPInitializersIntroductionRate))
        print("======================================================================")
        print("JOP Trampoline Gadgets:")
        print("Count Difference: " + str(self.JOPTrampolinesCountDiff))
        print("Reduction Rate: " + rate_format.format(self.JOPTrampolinesCountReduction))
        print("Introduced Count: " + str(len(self.JOPTrampolinesIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.JOPTrampolinesIntroductionRate))
        print("======================================================================")
        print("COP Dispatcher Gadgets:")
        print("Count Difference: " + str(self.COPDispatchersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPDispatchersCountReduction))
        print("Introduced Count: " + str(len(self.COPDispatchersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.COPDispatchersIntroductionRate))
        print("======================================================================")
        print("COP Data Loader Gadgets:")
        print("Count Difference: " + str(self.COPDataLoadersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPDataLoadersCountReduction))
        print("Introduced Count: " + str(len(self.COPDataLoadersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.COPDataLoadersIntroductionRate))
        print("======================================================================")
        print("COP Initializer Gadgets:")
        print("Count Difference: " + str(self.COPInitializersCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPInitializersCountReduction))
        print("Introduced Count: " + str(len(self.COPInitializersIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.COPInitializersIntroductionRate))
        print("======================================================================")
        print("COP Strong Trampoline Gadgets:")
        print("Count Difference: " + str(self.COPStrongTrampolinesCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPStrongTrampolinesCountReduction))
        print("Introduced Count: " + str(len(self.COPStrongTrampolinesIntroducedSet)))
        print("Introduction Rate: " + rate_format.format(self.COPStrongTrampolinesIntroductionRate))
        print("======================================================================")
        print("COP Intrastack Pivot Gadgets:")
        print("Count Difference: " + str(self.COPIntrastackPivotsCountDiff))
        print("Reduction Rate: " + rate_format.format(self.COPIntrastackPivotsCountReduction))
        print("Introduced Count: " + str(len(self.COPIntrastackPivotsIntroducedSet)))
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

    @staticmethod
    def findEqualGadgets(originalList, variantList):
        equalGadgets = 0
        for originalGadget in originalList:
            for variantGadget in variantList:
                if Gadget.gadgetsEqual(originalGadget, variantGadget):
                    equalGadgets += 1
        return equalGadgets
