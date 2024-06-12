
import angr.sim_type
import ida_hexrays
import ida_funcs
import ida_name
import ida_kernwin
import ida_nalt
import idc 
import ida_idaapi
import idaapi

import angr
import re
import os
import pickle
import threading
import time
import builtins
import json
import importlib
import functools

import PyQt5.QtCore as QtCore

from ida_angr_lib.log import logger
from ida_angr_lib import globals
from ida_angr_lib import hooks
from ida_angr_lib import ida_painter

importlib.reload(hooks)
importlib.reload(ida_painter)

from angr.sim_type import SimTypePointer, SimTypeInt, SimTypeChar, SimTypeFloat, SimTypeDouble, SimTypeArray, SimStruct

# warning: x86_64 assumption on data type sizes
# maybe use archinfo?


# Global variable to stop analysis and related lock
should_stop = False
should_stop_lock = threading.Lock()
start_time = time.time()

# Event to signal the completion of the exploration
exploration_done_event = threading.Event()

config_path = os.path.join(os.path.dirname(__file__), "config.json")

with open(config_path, "r") as f:
    config = json.load(f)

g_timeout = config['timeout']


# ---------------------------------------------------------------
class undo_handler_t(idaapi.action_handler_t):
    """Helper internal class to execute the undo-able user function"""
    id = 0
    def __init__(self, callable, *args, **kwargs):
        idaapi.action_handler_t.__init__(self)
        self.id += 1
        self.callable   = callable
        self.args       = args
        self.kwargs     = kwargs
        self.result     = None


    def activate(self, ctx):
        self.result = self.callable(*self.args, **self.kwargs)
        return 0


    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



# ---------------------------------------------------------------
class undoable_t:
    """Callable class that invokes the user's function via
    process_ui_actions(). This will create an undo point and
    hence making the function 'undoable'
    """
    def __init__(self, callable):
        self.callable = callable

    
    def __call__(self, *args, **kwargs):
        ah   = undo_handler_t(self.callable, *args, **kwargs)
        desc = idaapi.action_desc_t(
                    f"ida_undo_{self.callable.__name__}_{ah.id}",
                    f"IDAPython: {self.callable.__name__}",
                    ah)

        if not idaapi.register_action(desc):
            raise(f'Failed to register action {desc.name}')

        idaapi.process_ui_action(desc.name)
        idaapi.unregister_action(desc.name)

        return ah.result


    @staticmethod
    def undo():
        idaapi.process_ui_action('Undo')


undoable = lambda callable: undoable_t(callable)

class ClockWatcher(angr.exploration_techniques.ExplorationTechnique):

    def __init__(self, timeout):
        super().__init__()

        self.timeout = timeout
        self.start_time = time.time()
        logger.debug(f"Timeout set at {self.timeout}")

    def step(self, simgr, stash='active', **kwargs):
        with should_stop_lock:
            if should_stop:
                logger.debug("User cancelled!")
                simgr.move(from_stash="active", to_stash="timeout")
                return simgr
            
        if time.time() - self.start_time > self.timeout:
            logger.debug(f"Analysis timeout")
            simgr.move(from_stash="active", to_stash="timeout")
            return simgr
            
        return simgr.step(stash=stash, **kwargs)


class ToMainthread(QtCore.QObject):
    """
    A Qt object whose sole purpose is to execute code on the mainthread.

    Below, we define a Qt signal called 'mainthread'. Any thread can emit() this
    signal, where it will be handled in the main application thread.
    """
    mainthread = QtCore.pyqtSignal(object)

    def __init__(self):
        super(ToMainthread, self).__init__()

        #
        # from any thread, one can call 'mainthread.emit(a_function)', passing
        # in a callable object (a_function) which will be executed (through the
        # lambda) on the main application thread.
        #

        self.mainthread.connect(lambda x: x())


def execute_paint(function):
    """
    A function decorator to safely paint the IDA database from any thread.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        #
        # the first argument passed to this decorator will be the
        # IDAPainter class instance
        #

        ida_painter = args[0]

        #
        # we wrap up the remaining args (and paint function) into a single
        # packaged up callable object (a functools.partial)
        #

        ff = functools.partial(function, *args, **kwargs)

        #
        # if we are using a 'bugged' downlevel version of IDA, package another
        # callable to 'synchronize' a database write. This callable will get
        # passed to the main thread and executed through the Qt event loop.
        #
        # the execute_sync should technically happy in-line, avoiding the
        # possibility of deadlocks or aborts as described above.
        #

        if idaapi.IDA_SDK_VERSION < 710:
            fff = functools.partial(idaapi.execute_sync, ff, idaapi.MFF_WRITE)
            ida_painter._signal.mainthread.emit(fff)
            return idaapi.BADADDR

        #
        # in IDA 7.1, the MFF_NOWAIT bug is definitely fixed, so we can just
        # use it to schedule our paint action ... as designed.
        #

        return idaapi.execute_sync(ff, idaapi.MFF_NOWAIT | idaapi.MFF_WRITE)
    return wrapper        


class IDAPainter():

    def __init__(self):

        self._signal = ToMainthread()

    @execute_paint
    def paint_ea(self, ea):

        ida_painter.color_lines(ea)



def get_suffix_path_relative_to_idb(suffix):

    binary_path = globals.binary_path
    basename = os.path.basename(binary_path)
    suffixed_path = basename + suffix
    basepath = os.path.dirname(binary_path)
    return os.path.join(basepath, suffixed_path)

def get_path_relative_to_idb(path):

    binary_path = globals.binary_path
    basepath = os.path.dirname(binary_path)
    return os.path.join(basepath, path)


def create_angr_project():

    binary_path = globals.binary_path
    basename = os.path.basename(binary_path)
    proj_cache_file = basename + ".proj.pickle"
    cfg_cache_file = basename + ".cfg.pickle"
    basepath = os.path.dirname(binary_path)
    proj_cache_file = os.path.join(basepath, proj_cache_file)
    cfg_cache_file = os.path.join(basepath, cfg_cache_file)
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
    if os.path.exists(cfg_cache_file):
        logger.debug(f"Found cache file {cfg_cache_file}, loading it...")
        with open(cfg_cache_file, "rb") as f:
            globals.cfg = pickle.load(f)
    else:
        globals.cfg = globals.proj.analyses.CFGFast()
        with open(cfg_cache_file, "wb") as f:
            pickle.dump(globals.cfg, f, protocol=-1)

    logger.debug("CFG ready")
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
    elif "_DWORD" in param_type_str:
        param_type_str = param_type_str.replace("_DWORD", "int") # cparser doesn't like it

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

    if "(" in func_name:
        func_name = func_name[:func_name.index('(')]

    if " " in func_name:
        func_name = func_name.split()[-1]

    logger.debug(f"Long name: {func_name}")
    
    # Decompile the function
    cfunc = ida_hexrays.decompile(func)
    if not cfunc:
        logger.error("Failed to decompile the function.")
        return
    
    # Get the function prototype
    prototype = cfunc.type
    prototype_str = str(prototype)

    logger.debug(f"prototype_str: {prototype_str}")
    
    # Insert the function name into the prototype string
    # Find the position to insert the function name
    insert_pos = prototype_str.find('(')
    if insert_pos == -1:
        logger.error("Failed to find the position to insert the function name.")
        return
    
    # Construct the full prototype with the function name
    full_prototype = prototype_str[:insert_pos] + ' ' + func_name + prototype_str[insert_pos:]
    full_prototype = full_prototype.replace("__fastcall ", "")
    full_prototype = full_prototype.replace("__stdcall ", "")
    full_prototype = full_prototype.replace("__cdecl", "")
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
    if "extern-address" in human_str and state.addr not in globals.hooked_functions:
        logger.error(f"Implement hook for {hex(state.addr)} ({human_str})")
        raise Exception("Hook not implemented")


def build_call_state_async(prototype, prototype_arg_str, ea):

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

    logger.debug(f"Prototype: {prototype}")
    globals.state = globals.proj.factory.call_state(
        ea,
        *symbolic_args,
        cc=globals.mycc,
        prototype=prototype
    )

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    globals.proj.hook_symbol('__acrt_iob_func', hooks.acrt_iob_func())
    globals.proj.hook_symbol('__stdio_common_vfprintf', hooks.stdio_common_vfprintf())
    hooks.set_all_hooks(globals.proj, globals.hooked_functions, globals.mycc)

    globals.state.inspect.b('call', when=angr.BP_BEFORE, action=inspect_call)
    #globals.state.inspect.b('instruction', when=angr.BP_BEFORE, action=instruction_hook)
    #state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    builtins.__dict__['state'] = globals.state
    builtins.__dict__['proj'] = globals.proj


def update_coverage(*args, **kwargs):

    sm = args[0]
    
    for state in sm.stashes["active"]:

        addrs = state.history.bbl_addrs.hardcopy
        for insn_addr in addrs:
            if insn_addr not in globals.aggregated_cov:
                logger.debug(f"New address: {hex(insn_addr)}")
                globals.aggregated_cov.add(insn_addr)
                #globals.painter.paint_ea(insn_addr)

    
def instruction_hook(state):

    for addr in state.history.bbl_addrs.hardcopy:
        if addr not in globals.aggregated_cov:
            logger.debug(f"New address: {hex(addr)}")
            globals.aggregated_cov.add(addr)
            globals.painter.paint_ea(addr)

def explore_async():

    # Load the JSON file
    addresses_path = get_path_relative_to_idb("addresses.json")

    if not os.path.exists(addresses_path):
        logger.warning(f"You must create and populate {addresses_path} first")
        exploration_done_event.set()
        return

    with open(addresses_path, 'r') as f:
        data = json.load(f)

    # Extract the find and avoid addresses
    find_addresses = [int(item['address'], 16) if item['address'].startswith('0x') else item['address'] for item in data['find']]
    avoid_addresses = [int(item['address'], 16) if item['address'].startswith('0x') else item['address'] for item in data['avoid']]

    globals.simgr = globals.proj.factory.simgr(state)

    logger.debug(globals.simgr.active[0].regs.rip)

    globals.simgr = globals.proj.factory.simulation_manager(state)
    
    globals.simgr.use_technique(ClockWatcher(timeout=g_timeout))
    globals.simgr.use_technique(angr.exploration_techniques.Spiller())
    logger.debug(f"Exploring...find={find_addresses}, avoid={avoid_addresses}")
    globals.aggregated_cov = set()
    # Use the extracted addresses in your explore function
    globals.simgr.explore(find=find_addresses, avoid=avoid_addresses, step_func=update_coverage)
    
    # Signal that the exploration is done
    exploration_done_event.set()

    s = globals.simgr
    logger.debug(f'active: {len(s.active)}')
    logger.debug(f'found: {len(s.found)}')
    logger.debug(f'avoid: {len(s.avoid)}')
    logger.debug(f'deadended: {len(s.deadended)}')
    logger.debug(f'errored: {len(s.errored)}')
    logger.debug(f'unsat: {len(s.unsat)}')
    logger.debug(f'uncons: {len(s.unconstrained)}')
    logger.debug(f'timeout: {len(s.timeout) if hasattr(s, "timeout") else 0}')

    builtins.__dict__['simgr'] = globals.simgr
    
    logger.debug("Injected globals.simgr into builtins")

    if len(s.found) > 0:
        try:
            simgr_cache_path = get_suffix_path_relative_to_idb(".simgr.pickle")
            with open(simgr_cache_path, 'wb') as f:
                pickle.dump(globals.simgr, f, protocol=-1)
            logger.debug(f"Dumped simgr to {simgr_cache_path}")
        except:
            import traceback
            traceback.print_exc()


def build_call_state(ea):

    global should_stop
    #ida_idaapi.set_script_timeout(15)

    with should_stop_lock:
        should_stop = False

    prototype, prototype_arg_str = get_function_prototype(ea)
    globals.binary_path = ida_nalt.get_input_file_path()

    ida_kernwin.show_wait_box("Building call state....")

    try:
            
        e = threading.Thread(target=build_call_state_async, args=(prototype, prototype_arg_str, ea,))
        e.start()
        e.join()

    finally:
        ida_kernwin.hide_wait_box()


@undoable
def explore_from_here(ea):

    if globals.state is None:
        build_call_state(ea)


    globals.painter = IDAPainter()


    global should_stop

    with should_stop_lock:
        should_stop = False

    ida_kernwin.show_wait_box("angr is exploring....")

    exploration_thread = threading.Thread(target=explore_async)
    exploration_thread.start()

    try:
        # Periodically check if the exploration is done
        while not exploration_done_event.is_set():
            if ida_kernwin.user_cancelled() or time.time() - start_time > g_timeout * 2:
                logger.debug("Aborting...")
                with should_stop_lock:
                    should_stop = True
             
                break

            idc.qsleep(100)  # Sleep for 100 ms to avoid busy-waiting
    finally:
        ida_kernwin.hide_wait_box()
    
    if should_stop:
        print("Exploration was cancelled.")
    else:
        print("Exploration completed.")

    builtins.__dict__["aggregated_cov"] = globals.aggregated_cov
    builtins.__dict__["painter"] = globals.painter


    pass