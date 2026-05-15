# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running GSA

All commands must be run from the `src/` directory because imports are relative to it:

```bash
cd src
python3 GSA.py <original_binary> --variants <label>=<path> [options]
```

Example using sample data:
```bash
cd src
python3 GSA.py --output_metrics --output_console \
  ../samples/CHISEL/date/date-8.21.origin \
  --variants Reduced="../samples/CHISEL/date/date-8.21.reduced"
```

Key flags: `--output_metrics` (write CSV files), `--output_console` (print to stdout), `--output_locality` (gadget locality, slow), `--output_addresses` (angr CFG for function names, slow), `--output_simple` (single simplified CSV), `--output_tables <label>` (LaTeX format).

Results are written to `src/results/` by default (timestamped subdirectory).

## Dependencies

Install before running:
```bash
pip install ROPgadget angr numpy
```

There is no `pyproject.toml`, `requirements.txt`, or test suite.

## Architecture

The pipeline is: binary → ROPgadget → `GadgetSet` → `GadgetStats` → output files.

**`src/GSA.py`** — CLI entry point. Parses args, constructs one `GadgetSet` for the original and one per variant, creates a `GadgetStats` for each pair, then formats and writes all output files. All output formatting lives here.

**`src/static_analyzer/GadgetSet.py`** — Core analysis. Invokes `ROPgadget --binary <path> --all --multibr` via subprocess, parses output into `Gadget` objects, runs each through 13 elimination criteria, sorts survivors into typed collections (ROP/JOP/COP/Syscall and 10 special-purpose subtypes), deduplicates, scores, and computes expressivity. Optionally builds an angr CFG for source function lookup.

**`src/static_analyzer/GadgetStats.py`** — Comparison. Receives two `GadgetSet` objects; computes all differential metrics: count diffs, reduction rates, introduction rates, expressivity class changes, quality diffs, and (optionally) gadget locality. Uses Python set arithmetic on `gadget.instruction_string` strings for introduction/reduction; uses `repr(gadget)` (includes offset) for locality.

**`src/static_analyzer/Gadget.py`** — Single gadget. Parses a ROPgadget output line into offset + `Instruction` list. Implements all elimination checks (`is_gpi_only`, `clobbers_stack_pointer`, etc.) and scoring methods (`check_register_ops`, `check_memory_writes`, etc.). Two identity concepts: `is_equal` (same binary + offset + instructions, used for locality) vs `is_duplicate` (same instruction sequence regardless of offset/binary, used for deduplication).

**`src/static_analyzer/Instruction.py`** — Single instruction. Parses opcode/op1/op2 from a raw string. Holds two register family tables: `register_families` (includes byte registers al/ah/bl/etc.) and `word_register_families` (word-and-wider only). Static helpers: `get_operand_register_family`, `get_word_operand_register_family`, `is_constant`, `get_operand_as_constant`.

## Key Domain Concepts

**GPI** (Gadget Producing Instruction): the terminal instruction that transfers control — `ret` (ROP), `jmp` (JOP), `call` (COP), `syscall`/`int 0x80` (Syscall).

**Register families**: Registers are grouped by their architectural base (e.g., rax/eax/ax/al/ah = family 0, rsp/esp/sp/spl = family 7). Family lookups drive most classification and scoring logic.

**Quality score**: Starts at 0; increases for each side constraint that makes a gadget harder to use (memory writes, clobbered registers, negative stack offsets, etc.). Higher score = worse quality. Only gadgets with score ≤ 4.0 are counted toward expressivity classes.

**Expressivity classes**: Three frameworks measured — Practical ROP (11 classes), ASLR-proof Practical ROP (35 classes), Simple Turing Complete (17 classes). Each class represents a capability an attacker needs; `GadgetSet.classify_gadget` maps gadgets to the classes they satisfy.

**Special-purpose gadgets**: Classified by their role in advanced exploit chains: dispatchers and dataloaders (JOP/COP iteration), initializers and trampolines (setup/redirection), strong trampolines and intrastack pivots (COP only). These are separated from functional gadgets and never scored for quality.

**Locality**: The fraction of a variant's gadgets (by offset + instruction string) that also appear at the same address in the original. Measures how much ASLR-like offset randomization a transformation provides. Expensive to compute — requires cross-product comparison of `allGadgets` lists.
