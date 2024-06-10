
import angr.sim_type
import ida_hexrays
import ida_funcs
import ida_name
import ida_kernwin
import ida_nalt

import angr
import re
import os
import pickle


from ida_angr_lib.log import logger
from ida_angr_lib import globals

from angr.sim_type import SimTypePointer, SimTypeInt, SimTypeChar, SimTypeFloat, SimTypeDouble, SimTypeArray, SimStruct

# warning: x86_64 assumption on data type sizes
# maybe use archinfo?


def create_angr_project():

    binary_path = ida_nalt.get_input_file_path()
    globals.binary_path = binary_path
    basename = os.path.basename(binary_path)
    proj_cache_file = basename + ".proj.pickle"
    basepath = os.path.dirname(binary_path)
    proj_cache_file = os.path.join(basepath, proj_cache_file)
    
    logger.debug("Loading project...")

    if os.path.exists(proj_cache_file):
        logger.debug(f"Found cache file {proj_cache_file}, loading it....")
        with open(proj_cache_file, "rb") as project_file:
            globals.proj = pickle.load(project_file)
    else:

        if not os.path.exists(binary_path):
            logger.error(f"The IDB says the binary is at {binary_path} but it does not exist there.")
            return False
        
        globals.proj = angr.Project(globals.binary_path, auto_load_libs=False)
        
        with open(proj_cache_file, "wb") as project_file:
            pickle.dump(globals.proj, project_file, protocol=-1)

    logger.debug("Running CFG analysis")

    # Get control flow graph.
    globals.cfg = globals.proj.analyses.CFGFast()
    return True


def create_symbolic_variable(state, param_type_str, param_name):
    """
    Create a symbolic variable based on the parameter type.
    
    Args:
        state (angr.SimState): The current simulation state.
        param_type (str): The type of the parameter.
        param_name (str): The name of the parameter.
    
    Returns:
        angr.SimVariable: The symbolic variable.
    """
    # Type aliases
    if param_type_str == "ULONG*":
        param_type_str = "unsigned int*"

    param_type = angr.sim_type.parse_type(param_type_str, arch=state.arch)

    if param_type is None or not isinstance(param_type, angr.sim_type.SimType):
        logger.error(f"Unsupported type: {param_type_str}")

    logger.debug(f"Type: {param_type}")

    # Helper function to allocate memory and store a symbolic variable
    def allocate_and_store(size):
        symbolic_var = state.solver.BVS(param_name, size * 8)
        addr = state.heap.allocate(size)
        state.memory.store(addr, symbolic_var)
        return addr

    # Handle SimTypePointer
    if isinstance(param_type, SimTypePointer):
        size = 0x200  # Default size, adjust based on your needs
        return allocate_and_store(size)
    
    # Handle SimTypeInt
    if isinstance(param_type, SimTypeInt):
        
        logger.debug(f"Size: {param_type.size}")
        return state.solver.BVS(param_name, param_type.size)
    
    # Handle SimTypeFloat and SimTypeDouble
    if isinstance(param_type, (SimTypeFloat, SimTypeDouble)):
        logger.debug(f"Size: {param_type.size}")
        return state.solver.BVS(param_name, param_type.size)
    
    # Handle arrays
    # TODO
    array_match = re.match(r'(.+)\[(\d+)\]', param_type)
    if array_match:
        base_type, array_size = array_match.groups()
        array_size = int(array_size)
        if 'char' in base_type:
            size = array_size
        elif 'int8' in base_type:
            size = array_size
        elif 'int16' in base_type:
            size = array_size * 2
        elif 'int32' in base_type:
            size = array_size * 4
        elif 'int64' in base_type:
            size = array_size * 8
        elif 'float' in base_type:
            size = array_size * 4
        elif 'double' in base_type:
            size = array_size * 8
        else:
            raise ValueError(f"Unsupported array base type: {base_type}")
        return allocate_and_store(size)
    
    # Handle structures
    struct_match = re.match(r'struct\s+(\w+)', param_type)
    if struct_match:
        struct_name = struct_match.group(1)
        # For simplicity, treat the entire structure as a symbolic memory region
        size = 0x200  # TODO: make this an option
        return allocate_and_store(size)
    
    raise ValueError(f"Unsupported parameter type: {param_type}")


def get_function_prototype(ea):

    
    func = ida_funcs.get_func(ea)
    if not func:
        logger.error("No function found at the current address.")
        return
    
    # Get the function name
    func_name = ida_name.get_long_name(func.start_ea)
    if not func_name:
        logger.error("Failed to get the function name.")
        return
    
    # Decompile the function
    cfunc = ida_hexrays.decompile(func)
    if not cfunc:
        logger.error("Failed to decompile the function.")
        return
    
    # Get the function prototype
    prototype = cfunc.type
    prototype_str = str(prototype)
    
    # Insert the function name into the prototype string
    # Find the position to insert the function name
    insert_pos = prototype_str.find('(')
    if insert_pos == -1:
        logger.error("Failed to find the position to insert the function name.")
        return
    
    # Construct the full prototype with the function name
    full_prototype = prototype_str[:insert_pos] + ' ' + func_name + prototype_str[insert_pos:]
    full_prototype = full_prototype.replace("__fastcall ", "")
    full_prototype = full_prototype.replace("__int64", "int64_t")
    full_prototype = full_prototype.replace("ULONG *", "unsigned int*")
    return full_prototype, prototype_str[insert_pos:]


def parse_prototype(prototype):
    logger.debug(f"Parsing prototype: {prototype}")
    
    # Adjust the regex to handle cases where only parameters are provided
    match = re.match(r'(?:(.+?)\s+(\w+)\s*)?\((.*)\)', prototype)
    if not match:
        raise ValueError("Invalid prototype format")
    
    return_type, func_name, params = match.groups()
    
    # If return_type and func_name are None, it means only parameters were provided
    if return_type is None and func_name is None:
        return_type = "void"
        func_name = "unknown_function"
    
    param_list = params.split(',')
    
    param_info = []
    for param in param_list:
        param = param.strip()
        if param:  # Check if param is not an empty string
            # Handle cases where parameter names might be missing
            parts = param.rsplit(' ', 1)
            if len(parts) == 2:
                param_type, param_name = parts
            else:
                param_type, param_name = parts[0], None
            param_info.append((param_type, param_name))
    
    return return_type, func_name, param_info


def inspect_call(state):
    human_str = state.project.loader.describe_addr(state.addr)
    logger.debug(
        f'call {hex(state.addr)} ({human_str}) from {hex(state.history.addr)} ({state.project.loader.describe_addr(state.addr)})')
    if "extern-address" in human_str:
        logger.warning(f"Implement hook for {hex(state.addr)} ({human_str})")
        pass



def build_call_state(ea):

    prototype, prototype_arg_str = get_function_prototype(ea)

    logger.debug(prototype)

    if not create_angr_project():
        return

    state = globals.proj.factory.blank_state()
    return_type, func_name, param_info = parse_prototype(prototype_arg_str)

    symbolic_args = []
    for param_type, param_name in param_info:
        
        # TODO: do this properly
        if "**" in param_name:
            param_type = param_type.strip() + "**"
            param_name = param_name.replace("*", "")
        elif "*" in param_name:
            param_type = param_type.strip() + "*"
            param_name = param_name.replace("*", "")

        logger.debug(f"Creating symbolic var for {param_name} ({param_type})")
        symbolic_var = create_symbolic_variable(state, param_type, param_name)
        symbolic_args.append(symbolic_var)

    globals.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(globals.proj.arch)

    state = globals.proj.factory.call_state(
        ea,
        *symbolic_args,
        cc=globals.mycc,
        prototype=prototype
    )

    # state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    # state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.inspect.b('call', when=angr.BP_BEFORE, action=inspect_call)
    #state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    globals.simgr = globals.proj.factory.simgr(state)

    logger.debug(globals.simgr.active[0].regs.rip)