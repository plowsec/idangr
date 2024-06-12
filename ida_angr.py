import ida_kernwin
import idaapi
import ida_hexrays
import ida_funcs
import importlib
import sys
import builtins


from ida_angr_lib.log import logger
from ida_angr_lib.globals import simgr
from ida_angr_lib import ida_painter

sys.dont_write_bytecode = True
my_hooks = None

def clear_module_cache(module_name):
    if module_name in sys.modules:
        del sys.modules[module_name]

def paint_all_ea_in_function(ea):

    if not "painter" in builtins.__dict__ or not "aggregated_cov" in builtins.__dict__:
        logger.warning(f"Run an angr exploration first")
        return

    func = ida_funcs.get_func(ea)
    if func is not None:
        
        func_start = func.start_ea
        func_end = func.end_ea
        ea_in_function = [ea for ea in aggregated_cov if func_start <= ea <= func_end]
        logger.debug(f"{len(ea_in_function)} EAs to paint in current function...")
        for ea in ea_in_function:
            ida_painter.color_lines(ea)

builtins.__dict__["paint_all"] = paint_all_ea_in_function

class CustomRightClickHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current decompiled function
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            ea = vu.cfunc.entry_ea
            logger.debug("EA of the currently decompiled function: %x" % ea)
            logger.debug("Reloading extension code...")
            clear_module_cache('ida_angr_lib.ida_angr_main')
            
            import ida_angr_lib.ida_angr_main as ida_angr_main
            importlib.reload(ida_angr_main)
            ida_angr_main.build_call_state(ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExploreFromHereHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get the current decompiled function
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            ea = vu.cfunc.entry_ea
            logger.debug("EA of the currently decompiled function: %x" % ea)
            logger.debug("Exploring from here...")
            clear_module_cache('ida_angr_lib.ida_angr_main')
            
            import ida_angr_lib.ida_angr_main as ida_angr_main
            importlib.reload(ida_angr_main)
            ida_angr_main.explore_from_here(ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ShowCoverageHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        
        # Get the current decompiled function
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            func_ea = vu.cfunc.entry_ea
            paint_all_ea_in_function(func_ea)
              
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Define the actions
ACTION_NAME_BUILD_CALL_STATE = "idangr:right_click:build_call_state"
ACTION_LABEL_BUILD_CALL_STATE = "Build call state"
ACTION_SHORTCUT_BUILD_CALL_STATE = ""

ACTION_NAME_EXPLORE_FROM_HERE = "idangr:right_click:explore_from_here"
ACTION_LABEL_EXPLORE_FROM_HERE = "Explore from here"
ACTION_SHORTCUT_EXPLORE_FROM_HERE = ""

ACTION_NAME_SHOW_COVERAGE = "idangr:right_click:show_cov"
ACTION_LABEL_SHOW_COVERAGE = "Show angr coverage in current function"
ACTION_SHORTCUT_SHOW_COVERAGE = ""

def register_action():
    action_desc_build_call_state = ida_kernwin.action_desc_t(
        ACTION_NAME_BUILD_CALL_STATE,
        ACTION_LABEL_BUILD_CALL_STATE,
        CustomRightClickHandler(),
        ACTION_SHORTCUT_BUILD_CALL_STATE,
        "Build call state for current function",
        -1
    )

    action_desc_explore_from_here = ida_kernwin.action_desc_t(
        ACTION_NAME_EXPLORE_FROM_HERE,
        ACTION_LABEL_EXPLORE_FROM_HERE,
        ExploreFromHereHandler(),
        ACTION_SHORTCUT_EXPLORE_FROM_HERE,
        "Explore from the current function",
        -1
    )

    action_desc_show_coverage = ida_kernwin.action_desc_t(
        ACTION_NAME_SHOW_COVERAGE,
        ACTION_LABEL_SHOW_COVERAGE,
        ShowCoverageHandler(),
        ACTION_SHORTCUT_SHOW_COVERAGE,
        "Show angr coverage in current function",
        -1
    )

    # Register the actions
    res1 = ida_kernwin.register_action(action_desc_build_call_state)
    res2 = ida_kernwin.register_action(action_desc_explore_from_here)
    res3 = ida_kernwin.register_action(action_desc_show_coverage)
    logger.debug(f"Register action result (Build call state): {res1}")
    logger.debug(f"Register action result (Explore from here): {res2}")
    logger.debug(f"Register action result (Show coverage): {res3}")

    return res1 and res2


def unregister_action():
    res1 = ida_kernwin.unregister_action(ACTION_NAME_BUILD_CALL_STATE)
    res2 = ida_kernwin.unregister_action(ACTION_NAME_EXPLORE_FROM_HERE)
    res2 = ida_kernwin.unregister_action(ACTION_NAME_SHOW_COVERAGE)
    logger.debug(f"Unregister action result (Build call state): {res1}")
    logger.debug(f"Unregister action result (Explore from here): {res2}")
    logger.debug(f"Unregister action result (Show coverage): {res3}")


class my_hooks_t(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            res1 = ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_BUILD_CALL_STATE)
            res2 = ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_EXPLORE_FROM_HERE)
            
            if not ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME_SHOW_COVERAGE) or not res1 or not res2:
                logger.error(f"Failed attach_action_to_popup")

class AngrPlugin(idaapi.plugin_t):
    
    flags = idaapi.PLUGIN_KEEP
    comment = "Angr integration plugin"
    help = "Integrates angr with IDA Pro"
    wanted_name = "Angr Plugin"
    wanted_hotkey = "Ctrl-Shift-A"

    def init(self):
        logger.debug("Initializing Angr Plugin")
        if register_action():
            global my_hooks
            my_hooks = my_hooks_t()
            my_hooks.hook()
            logger.debug("UI Hooks set up")
            return idaapi.PLUGIN_OK
        else:
            return idaapi.PLUGIN_SKIP

    def term(self):
        logger.debug("Terminating Angr Plugin")

        # idk why but this is called immediately after init?
        
        """
        if my_hooks:
            my_hooks.unhook()
            logger.debug("UI Hooks removed")
        unregister_action()
        """

    def run(self, arg):
        logger.debug("Angr Plugin is running")

def PLUGIN_ENTRY():
    return AngrPlugin()