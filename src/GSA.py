#!/usr/bin/python3
"""
Analyzer
This script's primary purpose is compare a binary with its debloated variants to generate security oriented metrics for
determining if a debloating operation improved security.  It takes as input an original binary, and a dictionary of
variant names and their associated debloated variants. It produces as output:

    1) A CSV file containing both individual and comparative measures of the original gadget set and its variants.
    2) Console output summarizing an overall assessment of security improvement for each variant
    3) A text file containing the address of gadgets that cause measurable decreases in security.

This analyzer is built on existing tools. It requires a variant of ROPgadget made available by SRI and angr. See the
README included with this project for more information.

"""

# Standard Library Imports
import argparse
import sys

# Third Party Imports


# Local Imports
from utility import *
from static_analyzer.GadgetSet import GadgetSet
from static_analyzer.GadgetStats import GadgetStats

# Parse Arguments
parser = argparse.ArgumentParser()
parser.add_argument("original", help="Original program binary.", type=str)
parser.add_argument("debloated_variants", help="Python dictionary of variant names and relative paths.  Example: '{<variant_name>:<file_path>, ...}' ", type=str)
parser.add_argument("--output_metrics", help="Output metric data as a CSV file.", action='store_true')
parser.add_argument("--output_addresses", help="Output addresses of sensitive gadgets as a CSV file.", action='store_true')
args = parser.parse_args()

# Start Evaluating
print("Starting Gadget Set Analyzer")
print("Analyzing original package located at: " + args.original)

# Create Gadget sets for original and all variants
original = GadgetSet("original", args.original, False)

variants = []
variants_dict = eval(args.debloated_variants)
for key in variants_dict.keys():
    filepath = variants_dict.get(key)
    print("Analyzing variant package [" + key + "] located at: " + filepath)
    variants.append(GadgetSet(key, filepath, args.output_addresses))

# Calculate Gadget Stats for the original and each variant
stats = []
for variant in variants:
    stats.append(GadgetStats(original, variant))

# If file output is desired, create an output directory and write it.
if args.output_metrics or args.output_addresses:
    # Create a timestamped results folder
    try:
        directory_name = create_output_directory("results/analyzer_results_")
    except OSError as osErr:
        print("An OS Error occurred during creation of results directory: " + osErr.strerror)
        sys.exit("Results cannot be logged, aborting operation...")
    print("Metrics will be written to " + directory_name)

if args.output_metrics:
    print("Writing Metrics to files.")
    rate_format = "{:.1%}"

    # Output file 1: Gadget Counts/Reduction, Total and by Category
    file_lines = ["Package Variant,Total Gadgets,ROP Gadgets,JOP Gadgets,COP Gadgets\r"]
    orig_counts = original.name + "," + str(len(original.totalUniqueGadgets))
    orig_counts = orig_counts + "," + str(len(original.ROPGadgets))
    orig_counts = orig_counts + "," + str(len(original.JOPGadgets))
    orig_counts = orig_counts + "," + str(len(original.COPGadgets)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," + str(len(stat.variant.totalUniqueGadgets)) + " (" + str(stat.totalUniqueCountDiff) + "; " + rate_format.format(stat.totalUniqueCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.ROPGadgets)) + " (" + str(stat.ROPCountDiff) + "; " + rate_format.format(stat.ROPCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.JOPGadgets)) + " (" + str(stat.JOPCountDiff) + "; " + rate_format.format(stat.JOPCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.COPGadgets)) + " (" + str(stat.COPCountDiff) + "; " + rate_format.format(stat.COPCountReduction) + ")\r"
        file_lines.append(stat_counts)

    try:
        file = open(directory_name + "/GadgetCounts_Reduction.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output file 2: Gadget Introduction Counts/Rates
    file_lines = ["Package Variant,Total Gadgets,Total Gadgets Introduced,Total Introduction Rate,ROP Gadgets,ROP Gadgets Introduced,ROP Introduction Rate,JOP Gadgets,JOP Gadgets Introduced,JOP Introduction Rate,COP Gadgets,COP Gadgets Introduced,COP Introduction Rate\r"]
    orig_counts = original.name + "," + str(len(original.totalUniqueGadgets)) + ", , ,"
    orig_counts = orig_counts + str(len(original.ROPGadgets)) + ", , ,"
    orig_counts = orig_counts + str(len(original.JOPGadgets)) + ", , ,"
    orig_counts = orig_counts + str(len(original.COPGadgets)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," + str(len(stat.variant.totalUniqueGadgets)) + ","
        stat_counts = stat_counts + str(len(stat.totalUniqueIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.totalUniqueIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.ROPGadgets)) + ","
        stat_counts = stat_counts + str(len(stat.ROPIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.ROPIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.JOPGadgets)) + ","
        stat_counts = stat_counts + str(len(stat.JOPIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.JOPIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.COPGadgets)) + ","
        stat_counts = stat_counts + str(len(stat.COPIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPIntroductionRate) + "\r"
        file_lines.append(stat_counts)
    try:
        file = open(directory_name + "/Gadget_Introduction_Counts_Rate.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output file #3: Gadget Count Introduction
    # Part 1: ROP / JOP Special Purpose Gadgets
    file_lines = ["ROP and JOP Special Purpose Gadgets\r",
                  "Package Variant,Syscall Gadgets,JOP Dispatcher Gadgets,JOP Dataloader Gadgets,JOP Initializers,JOP Trampolines\r"]
    orig_counts = original.name + "," + str(len(original.SysGadgets))
    orig_counts = orig_counts + "," + str(len(original.JOPDispatchers))
    orig_counts = orig_counts + "," + str(len(original.JOPDataLoaders))
    orig_counts = orig_counts + "," + str(len(original.JOPInitializers))
    orig_counts = orig_counts + "," + str(len(original.JOPTrampolines)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," + str(len(stat.variant.SysGadgets)) + " (" + str(stat.SysCountDiff) + "; " + rate_format.format(stat.SysCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.JOPDispatchers)) + " (" + str(stat.JOPDispatchersCountDiff) + "; " + rate_format.format(stat.JOPDispatchersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.JOPDataLoaders)) + " (" + str(stat.JOPDataLoadersCountDiff) + "; " + rate_format.format(stat.JOPDataLoadersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.JOPInitializers)) + " (" + str(stat.JOPInitializersCountDiff) + "; " + rate_format.format(stat.JOPInitializersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.JOPTrampolines)) + " (" + str(stat.JOPTrampolinesCountDiff) + "; " + rate_format.format(stat.JOPTrampolinesCountReduction) + ")\r"
        file_lines.append(stat_counts)

    # Part 2: COP Special Purpose Gadgets
    file_lines.append("\r\r\r\r")
    file_lines.append("COP Special Purpose Gadgets\r")
    file_lines.append("Package Variant,COP Dispatcher Gadgets,COP Dataloader Gadgets,COP Initializers,COP Strong Trampoline Gadgets,COP Intra-stack Pivot Gadgets\r")
    orig_counts = original.name + "," + str(len(original.COPDispatchers))
    orig_counts = orig_counts + "," + str(len(original.COPDataLoaders))
    orig_counts = orig_counts + "," + str(len(original.COPInitializers))
    orig_counts = orig_counts + "," + str(len(original.COPStrongTrampolines))
    orig_counts = orig_counts + "," + str(len(original.COPIntrastackPivots)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," +  str(len(stat.variant.COPDispatchers)) + " (" + str(stat.COPDispatchersCountDiff) + "; " + rate_format.format(stat.COPDispatchersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.COPDataLoaders)) + " (" + str(stat.COPDataLoadersCountDiff) + "; " + rate_format.format(stat.COPDataLoadersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.COPInitializers)) + " (" + str(stat.COPInitializersCountDiff) + "; " + rate_format.format(stat.COPInitializersCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.COPStrongTrampolines)) + " (" + str(stat.COPStrongTrampolinesCountDiff) + "; " + rate_format.format(stat.COPStrongTrampolinesCountReduction) + "),"
        stat_counts = stat_counts + str(len(stat.variant.COPIntrastackPivots)) + " (" + str(stat.COPIntrastackPivotsCountDiff) + "; " + rate_format.format(stat.COPIntrastackPivotsCountReduction) + ")\r"
        file_lines.append(stat_counts)

    try:
        file = open(directory_name + "/SpecialPurpose_GadgetCounts_Reduction.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output File 4: Special Purpose Gadget Introduction Counts/Rates
    # Part 1: ROP and JOP Special Purpose Gadgets
    file_lines = ["ROP and JOP Special Purpose Gadget Introduction Data\r",
                  "Package Variant,Syscall Gadgets,Syscall Gadgets Introduced,Syscall Gadget Introduction Rate," +
                  "JOP Dispatcher Gadgets,JOP Dispatcher Gadgets Introduced,JOP Dispatcher Gadget Introduction Rate," +
                  "JOP Dataloader Gadgets,JOP Dataloader Gadgets Introduced,JOP Dataloader Gadget Introduction Rate," +
                  "JOP Initializer Gadgets,JOP Initializer Gadgets Introduced,JOP Initializer Gadget Introduction Rate," +
                  "JOP Trampoline Gadgets,JOP Trampoline Gadgets Introduced,JOP Trampoline Gadget Introduction Rate\r"]
    orig_counts = original.name + "," + str(len(original.SysGadgets)) + ", , ,"
    orig_counts = orig_counts + str(len(original.JOPDispatchers)) + ", , ,"
    orig_counts = orig_counts + str(len(original.JOPDataLoaders)) + ", , ,"
    orig_counts = orig_counts + str(len(original.JOPInitializers)) + ", , ,"
    orig_counts = orig_counts + str(len(original.JOPTrampolines)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," + str(len(stat.variant.SysGadgets)) + ","
        stat_counts = stat_counts + str(len(stat.SysIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.SysIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.JOPDispatchers)) + ","
        stat_counts = stat_counts + str(len(stat.JOPDispatchersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.JOPDispatchersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.JOPDataLoaders)) + ","
        stat_counts = stat_counts + str(len(stat.JOPDataLoadersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.JOPDataLoadersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.JOPInitializers)) + ","
        stat_counts = stat_counts + str(len(stat.JOPInitializersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.JOPInitializersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.JOPTrampolines)) + ","
        stat_counts = stat_counts + str(len(stat.JOPTrampolinesIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.JOPTrampolinesIntroductionRate) + "\r"
        file_lines.append(stat_counts)

    # Part 2: COP Special Purpose Gadgets
    file_lines.append("\r\r\r\r")
    file_lines.append("COP Special Purpose Gadget Introduction Data\r")
    file_lines.append("Package Variant,COP Dispatcher Gadgets,COP Dispatcher Gadgets Introduced,COP Dispatcher Gadget Introduction Rate," +
                      "COP Dataloader Gadgets,COP Dataloader Gadgets Introduced,COP Dataloader Gadget Introduction Rate," +
                      "COP Initializer Gadgets,COP Initializer Gadgets Introduced,COP Initializer Gadget Introduction Rate," +
                      "COP Strong Trampoline Gadgets,COP Strong Trampoline Gadgets Introduced,COP Strong Trampoline Gadget Introduction Rate," +
                      "COP Intra-stack Pivot Gadgets,COP Intra-stack Pivot Gadgets Introduced,COP Intra-stack Pivot Gadget Introduction Rate\r")

    orig_counts = original.name + "," + str(len(original.COPDispatchers)) + ", , ,"
    orig_counts = orig_counts + str(len(original.COPDataLoaders)) + ", , ,"
    orig_counts = orig_counts + str(len(original.COPInitializers)) + ", , ,"
    orig_counts = orig_counts + str(len(original.COPStrongTrampolines)) + ", , ,"
    orig_counts = orig_counts + str(len(original.COPIntrastackPivots)) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_counts = stat.variant.name + "," + str(len(stat.variant.COPDispatchers)) + ","
        stat_counts = stat_counts + str(len(stat.COPDispatchersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPDispatchersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.COPDataLoaders)) + ","
        stat_counts = stat_counts + str(len(stat.COPDataLoadersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPDataLoadersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.COPInitializers)) + ","
        stat_counts = stat_counts + str(len(stat.COPInitializersIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPInitializersIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.COPStrongTrampolines)) + ","
        stat_counts = stat_counts + str(len(stat.COPStrongTrampolinesIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPStrongTrampolinesIntroductionRate) + ","
        stat_counts = stat_counts + str(len(stat.variant.COPIntrastackPivots)) + ","
        stat_counts = stat_counts + str(len(stat.COPIntrastackPivotsIntroducedSet)) + ","
        stat_counts = stat_counts + rate_format.format(stat.COPIntrastackPivotsIntroductionRate) + "\r"
        file_lines.append(stat_counts)

    try:
        file = open(directory_name + "/SpecialPurpose_Gadget_Introduction_Counts_Rate.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output File 5: Gadget Expressivity Classes Fulfilled By Variant
    orig_simple_tc = original.simpleTuringCompleteClasses

    file_lines = ["Package Variant,Simple Turing Completeness\r"]
    orig_counts = original.name + ","
    orig_counts = orig_counts + str(orig_simple_tc) + "\r"
    file_lines.append(orig_counts)

    for stat in stats:
        stat_simple_tc = stat.variant.simpleTuringCompleteClasses
        stat_counts = stat.variant.name + "," + str(stat_simple_tc) + " (" + str(stat.simpleTuringCompleteCountDiff) + ")\r"
        file_lines.append(stat_counts)

    try:
        file = open(directory_name + "/Expressivity_Counts.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output File 6: Overall Gadget Locality
    file_lines = ["Package Variant,Gadget Locality\r"]

    for stat in stats:
        stat_locality = stat.variant.name + "," + rate_format.format(stat.gadgetLocality) + "\r"
        file_lines.append(stat_locality)

    try:
        file = open(directory_name + "/Gadget Locality.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)

    # Output File 7: Average Gadget Quality (and count of quality functional gadgets)
    file_lines = ["Package Variant,Quality ROP Gadgets,Average ROP Gadget Quality,Quality JOP Gadgets,Average JOP Gadget Quality,Quality COP Gadgets,Average COP Gadget Quality\r"]

    orig_quality = original.name + "," + str(original.keptQualityROPGadgets) + "," + str(original.averageROPQuality)
    orig_quality += "," + str(original.keptQualityJOPGadgets) + "," + str(original.averageJOPQuality)
    orig_quality += "," + str(original.keptQualityCOPGadgets) + "," + str(original.averageCOPQuality) + "\r"
    file_lines.append(orig_quality)

    for stat in stats:
        stat_quality = stat.variant.name + "," + str(stat.variant.keptQualityROPGadgets) + " (" + str(stat.keptQualityROPCountDiff) + "),"
        stat_quality += str(stat.variant.averageROPQuality) + " (" + str(stat.averageROPQualityDiff) + "),"
        stat_quality += str(stat.variant.keptQualityJOPGadgets) + " (" + str(stat.keptQualityJOPCountDiff) + "),"
        stat_quality += str(stat.variant.averageJOPQuality) + " (" + str(stat.averageJOPQualityDiff) + "),"
        stat_quality += str(stat.variant.keptQualityCOPGadgets) + " (" + str(stat.keptQualityCOPCountDiff) + "),"
        stat_quality += str(stat.variant.averageCOPQuality) + " (" + str(stat.averageCOPQualityDiff) + ")\r"
        file_lines.append(stat_quality)

    try:
        file = open(directory_name + "/Gadget Quality.csv", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)


# Output File 8: Suspected function names containing introduced special purpose gadgets.
if args.output_addresses:
    print("Writing function names associated with special purpose gadgets to files.")
    file_lines = []
    for stat in stats:
        file_lines.append("Sensitive gadgets introduced in variant: " + stat.variant.name + "\r")
        specialSets = [stat.SysIntroducedGadgets, stat.JOPDispatchersIntroducedGadgets,
                       stat.JOPDataLoadersIntroducedGadgets, stat.JOPInitializersIntroducedGadgets,
                       stat.JOPTrampolinesIntroducedGadgets, stat.COPDispatchersIntroducedGadgets,
                       stat.COPDataLoadersIntroducedGadgets, stat.COPInitializersIntroducedGadgets,
                       stat.COPStrongTrampolinesIntroducedGadgets, stat.COPIntrastackPivotsIntroducedGadgets]
        for specialSet in specialSets:
            for gadget in specialSet:
                file_lines.append("Gadget: " + str(gadget.instructions) + "\r")
                file_lines.append("Found at offset: " + gadget.offset + "\r")
                function = stat.variant.getFunction(gadget.offset)
                if function is None:
                    file_lines.append("No associated function found.\r")
                else:
                    file_lines.append("Most likely location in source code: " + function + "\r")
        file_lines.append("----------------------------------------------------------\r")

    try:
        file = open(directory_name + "/Likely_Gadget_Locations.txt", "w")
        file.writelines(file_lines)
        file.close()
    except OSError as osErr:
        print(osErr)
