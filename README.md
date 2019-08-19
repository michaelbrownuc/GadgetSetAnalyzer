# GadgetSetAnalyzer
A security-oriented static binary analysis tool for comparing the quantity and quality of code reuse gadget sets in program variants.  

## Description
The analyzer component is an automated tool for gathering security oriented data on the effects of software debloating. It takes as input an original software package binary that has not been debloated, and at least one debloated variant of that package. It produces as output the following data files:

 1. Gadget Expressivity Change: The change in expressivity between the original package and each variant.
 2. Gadget Count Reduction: The change in overall gadget count between the original package and each variant.
 3. Gadget Introduction: The rate at which new gadgets are introduced by software debloating.
 4. Special Purpose Gadget Count Reduction: Same as 2, but for sepcial purpose gadgets.
 5. Special Purpose Gadget Introduction: Same as 3, but for special purpose gadgets.
 6. Likely Gadget Locations: For each introduced special purpose gadget, the most likely function name in source where the gadget was introduced.
 7. Gadget Locality: The percentage of gadgets in a variant set that are also in present in the original set and also at the same offset.

## Dependencies
The static analyzer is dependent upon the following third party packages:

 1. ROPgadget (SRI verison) - for collecting gadget based information from binaries.
 2. angr - for finding source code functions associated with introduced gadgets.

## Installing
To install the analyzer:

 1. Install ROPgadget (https://github.com/SRI-CSL/ROPgadget)
 2. Install angr (https://docs.angr.io/introductory-errata/install)
 3. Clone this repo


## Running
The analyzer has 2 optional inputs:

 1. Output Metrics (--output_metrics): Indicates that the analyzer should produce output files 1-5.
 2. Output Addresses (--output_addresses): Indicates that the analyzer should produce output file 6.

The analyzer has 2 required inputs:

 1. Original Binary: Filepath to the original binary.
 2. Variant Labels / Binaries: Python Dictionaty consisting of variant names and filepaths to their binaries.

Example invocation:
```
python analyzer.py --output_metrics --output_addresses ./originals/date/date-8.21 "{'Aggressive':'./variants/date/date-8.21.reduced'}"
```
