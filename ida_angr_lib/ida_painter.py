import idc
import idaapi
import ida_hexrays
import idautils
from functools import lru_cache


import time


class NodeMetadata:
    def __init__(self, start_ea, end_ea, node_id):
        self.address = start_ea
        self.end_ea = end_ea
        self.id = node_id
        self.instructions = self._collect_instructions(start_ea, end_ea)

    def _collect_instructions(self, start_ea, end_ea):
        instructions = []
        ea = start_ea
        while ea < end_ea:
            instructions.append((ea, idc.GetDisasm(ea)))
            ea = idc.next_head(ea, end_ea)
        return instructions

class FunctionMetadata:
    def __init__(self, func):
        self.address = func.start_ea
        self.nodes = self._collect_nodes(func)

    def _collect_nodes(self, func):
        nodes = {}
        flowchart = idaapi.qflow_chart_t("", func, idaapi.BADADDR, idaapi.BADADDR, 0)
        for node_id in range(flowchart.size()):
            node = flowchart[node_id]
            if node.start_ea != node.end_ea:
                nodes[node.start_ea] = NodeMetadata(node.start_ea, node.end_ea, node_id)
        return nodes

class DatabaseMetadata:
    def __init__(self):
        self.functions = self._collect_functions()
        self.instruction_to_node = self._map_instructions_to_nodes()

    def _collect_functions(self):
        functions = {}
        for func_ea in idautils.Functions():
            func = idaapi.get_func(func_ea)
            if func:
                functions[func.start_ea] = FunctionMetadata(func)
        return functions

    def _map_instructions_to_nodes(self):
        instruction_to_node = {}
        for func in self.functions.values():
            for node in func.nodes.values():
                for instr_ea, _ in node.instructions:
                    instruction_to_node[instr_ea] = node
        return instruction_to_node

    def get_node(self, address):
        return self.instruction_to_node.get(address, None)


class HashableDecompilationText:
    def __init__(self, decompilation_text):
        self.decompilation_text = decompilation_text

    def __hash__(self):
        return hash(tuple(line.line for line in self.decompilation_text))

    def __eq__(self, other):
        if not isinstance(other, HashableDecompilationText):
            return False
        return all(line1.line == line2.line for line1, line2 in zip(self.decompilation_text, other.decompilation_text))

    def __getattr__(self, attr):
        return getattr(self.decompilation_text, attr)

    def __getitem__(self, index):
        return self.decompilation_text[index]

    def __len__(self):
        return len(self.decompilation_text)

@lru_cache(maxsize=None)
def map_line2citem(decompilation_text):
    line2citem = {}
    for line_number in range(len(decompilation_text)):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)
    return line2citem

@lru_cache(maxsize=None)
def map_line2node(cfunc, metadata, line2citem_tuple):
    line2citem = {k: list(v) for k, v in line2citem_tuple}
    line2node = {}
    treeitems = cfunc.treeitems
    for line_number, citem_indexes in line2citem.items():
        nodes = set()
        for index in citem_indexes:
            try:
                item = treeitems[index]
                address = item.ea
            except IndexError:
                continue
            node = metadata.get_node(address)
            if node:
                nodes.add((node.address, address))
        line2node[line_number] = nodes
    return line2node
    
def lex_citem_indexes(line):
    i = 0
    indexes = []
    line_length = len(line)
    while i < line_length:
        if line[i] == idaapi.COLOR_ON:
            i += 1
            if ord(line[i]) == idaapi.COLOR_ADDR:
                i += 1
                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE
                indexes.append(citem_index)
                continue
        i += 1
    return indexes

def color_lines(ea, color=0x00FF00):
    idc.set_color(ea, idc.CIC_ITEM, color)
    
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays is not available.")
        return
    
    func = idaapi.get_func(ea)
    if not func:
        print(f"No function found at the given address {hex(ea)}.")
        return
    
    cfunc = ida_hexrays.decompile(func.start_ea)
    if not cfunc:
        print(f"Failed to decompile the function at address {hex(func.start_ea)}.")
        return
    
    pseudocode = cfunc.get_pseudocode()
    hashable_pseudocode = HashableDecompilationText(pseudocode)
    line2citem = map_line2citem(hashable_pseudocode)
    
    # Convert line2citem to a hashable type (tuple of tuples)
    line2citem_tuple = tuple((k, tuple(v)) for k, v in line2citem.items())
    
    line2node = map_line2node(cfunc, g_metadata, line2citem_tuple)
    exact_match_found = False
    
    for line_number, line_nodes in line2node.items():
        for node_address, instr_address in line_nodes:
            if ea == instr_address:
                pseudocode[line_number].bgcolor = color
                exact_match_found = True
                break

        if exact_match_found:
            break
    
    # If exact match is not found, try to find another address in the same basic block
    if not exact_match_found:
        node = g_metadata.get_node(ea)
        if node:
            for instr_ea, _ in reversed(node.instructions):
                if instr_ea != ea:
                    color_lines(instr_ea, color)
                    break
    
    vdui = ida_hexrays.get_widget_vdui(idaapi.get_current_widget())
    if vdui:
        vdui.refresh_view(True)

def restore_default_colors():
    print("Restoring default colors for all addresses.")
    for ea in idautils.Heads():
        idc.set_color(ea, idc.CIC_ITEM, idc.DEFCOLOR)
    print("Default colors restored.")

a = time.time()
g_metadata = DatabaseMetadata()

print(f"Collected metadata in {time.time()-a} seconds")    
