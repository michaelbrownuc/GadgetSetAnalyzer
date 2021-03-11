# GadgetSetAnalyzer
A security-oriented static binary analysis tool for comparing the quantity, quality, and locality of code reuse gadget sets in program variants.

If you use this tool in your research, please cite the following paper:

**Brown, Michael D., and Santosh Pande. "Is less really more? towards better metrics for measuring security improvements realized through software debloating." In 12th {USENIX} Workshop on Cyber Security Experimentation and Test ({CSET} 19). 2019.**[\[pdf\]](https://www.usenix.org/system/files/cset19-paper_brown.pdf)

GSA has been updated to include new metrics since the publication of this paper.  The expanded version of the paper that includes expanded metrics is available here:

**Brown, Michael D., and Santosh Pande. "Is Less Really More? Why Reducing Code Reuse Gadget Counts via
Software Debloating Doesn’t Necessarily Indicate Improved Security" arXiv:1902.10880v3 [cs.CR]. 2019.**[\[pdf\]](https://arxiv.org/pdf/1902.10880.pdf)

## Description
GSA is an automated tool for gathering security-oriented data on the effects of software transformation. It takes as input an original software package binary that has not been transformed, and at least one transformed variant of that package. It produces as output the following data files:

 1. Functional Gadget Set Expressivity Change: The change in gadget set expressivity (ROP) between the original package and each variant.
 2. Gadget Count Reduction: The change in overall gadget count between the original package and each variant.
 3. Gadget Introduction: The rate at which new gadgets are introduced by software transformation.
 4. Special Purpose Gadget Count Reduction: Same as 2, but for sepcial purpose gadgets.
 5. Special Purpose Gadget Introduction: Same as 3, but for special purpose gadgets.
 6. Gadget Locality: The percentage of gadgets in a variant set that are also in present in the original set and also at the same offset.
 7. Functional Gadget Set Quality Change: The change in quality (as measured by ease of use and the absence of side constraints) of the gadget set between the original package and each variant.
 8. Likely Gadget Locations: For each special purpose gadget in each variant binary, the most likely function name in source where the gadget was introduced.

## Dependencies
The static analyzer is dependent upon the following third party packages:

 1. ROPgadget - for collecting gadget based information from binaries.
 2. angr - for finding source code functions associated with introduced gadgets.

## Installing
To install GSA:

 1. Install ROPgadget (https://github.com/JonathanSalwan/ROPgadget)
 2. Install angr (https://docs.angr.io/introductory-errata/install)
 3. Clone this repo

## Running
GSA has 4 optional inputs:

 1. Output Metrics (--output_metrics): Indicates that GSA should produce output files 1-7.
 2. Output Addresses (--output_addresses): Indicates that GSA should produce output file 8. Ignored if output_metrics is not set. Takes extra time to use angr.
 3. Result Folder Name (--result_folder_name <name>): Indicates that GSA should place results for the run in results/<name> 
 4. Original Name (--original_name <name>): Indicates that GSA should use a specific <name> in the output for the original binary.

The analyzer has 2 required inputs:

 1. Original Binary: Filepath to the original binary.
 2. Variant Labels / Binaries: Python dictionary consisting of variant names and filepaths to their binaries.

Example invocation:
```
python GSA.py --output_metrics --output_addresses ./samples/CHISEL/date/date-8.21 "{'Aggressive':'./samples/CHISEL/date/date-8.21.reduced'}"
```
