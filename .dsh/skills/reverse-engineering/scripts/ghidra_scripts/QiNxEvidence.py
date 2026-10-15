# Qi-NX Ghidra headless script. Export address-linked function and call evidence.
# Arguments: <output-json-path> [max-functions]
# Copyright Qi-NX.

import json
import os

MAX_TOTAL_CALLS = 20000
MAX_CALLS_PER_FUNCTION = 128


def addr_record(address, image_base):
    image_offset = None
    if address.hasSameAddressSpace(image_base):
        bits = int(address.getAddressSpace().getSize())
        absolute = int(address.getUnsignedOffset())
        base = int(image_base.getUnsignedOffset())
        if absolute < 0:
            absolute += 1 << bits
        if base < 0:
            base += 1 << bits
        relative = absolute - base
        image_offset = ("0x%x" % relative if relative >= 0
                        else "-0x%x" % (-relative))
    return {
        "address": str(address),
        "address_space": str(address.getAddressSpace().getName()),
        "image_offset": image_offset,
    }


def run():
    args = getScriptArgs()
    if not args:
        raise RuntimeError("expected output JSON path")
    output_path = args[0]
    max_functions = int(args[1]) if len(args) > 1 else 20000
    program = currentProgram
    image_base = program.getImageBase()
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    functions = []
    callsite_total = 0
    total_seen = 0
    calls_truncated = False
    any_function_calls_truncated = False
    iterator = function_manager.getFunctions(True)

    while iterator.hasNext():
        function = iterator.next()
        total_seen += 1
        if len(functions) >= max_functions:
            break
        entry = function.getEntryPoint()
        calls = []
        function_calls_truncated = False
        body = function.getBody()
        instructions = listing.getInstructions(body, True)
        instruction_count = 0
        while instructions.hasNext():
            instruction = instructions.next()
            instruction_count += 1
            for reference in ref_manager.getReferencesFrom(instruction.getAddress()):
                if not reference.getReferenceType().isCall():
                    continue
                if callsite_total >= MAX_TOTAL_CALLS:
                    calls_truncated = True
                    function_calls_truncated = True
                    break
                destination = reference.getToAddress()
                callee = function_manager.getFunctionAt(destination)
                if callee is None:
                    callee = function_manager.getFunctionContaining(destination)
                name = callee.getName() if callee is not None else str(destination)
                calls.append({
                    "site": addr_record(instruction.getAddress(), image_base),
                    "target": addr_record(destination, image_base),
                    "name": name,
                    "mnemonic": instruction.getMnemonicString(),
                })
                callsite_total += 1
                if len(calls) >= MAX_CALLS_PER_FUNCTION:
                    function_calls_truncated = True
                    break
            if calls_truncated or len(calls) >= MAX_CALLS_PER_FUNCTION:
                break
        functions.append({
            "name": function.getName(),
            "signature": function.getPrototypeString(False, False),
            "entry": addr_record(entry, image_base),
            "size_bytes": int(body.getNumAddresses()),
            "instruction_count": instruction_count,
            "is_thunk": bool(function.isThunk()),
            "calls": calls,
            "calls_truncated": function_calls_truncated,
        })
        any_function_calls_truncated = (any_function_calls_truncated
                                        or function_calls_truncated)
        if calls_truncated:
            break

    data = {
        "ghidra_version": getGhidraVersion(),
        "format": program.getExecutableFormat(),
        "language": str(program.getLanguageID()),
        "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(image_base),
        "function_total": len(functions),
        "function_count_reported_by_ghidra": int(function_manager.getFunctionCount()),
        "callsite_total": callsite_total,
        "truncated": total_seen > max_functions or any_function_calls_truncated,
        "calls_truncated": calls_truncated,
        "functions": functions,
        "evidence_notes": [
            "image_offset is the address minus the Ghidra image base (RVA-like; format-dependent)",
            "calls are Ghidra call references; indirect or unresolved calls may be absent",
            "instruction_count and function boundaries come from Ghidra auto-analysis",
        ],
    }
    parent = os.path.dirname(output_path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    stream = open(output_path, "w")
    try:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
    finally:
        stream.close()


run()
