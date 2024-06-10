import ida_kernwin
import idaapi
import ida_hexrays
import importlib
import sys

from ida_angr_lib.log import logger


sys.dont_write_bytecode = True


def clear_module_cache(module_name):
    if module_name in sys.modules:
        del sys.modules[module_name]

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

# Define the action
ACTION_NAME = "idangr:right_click:handler"
ACTION_LABEL = "Build call state"
ACTION_SHORTCUT = ""

def register_action():
    action_desc = ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        CustomRightClickHandler(),
        ACTION_SHORTCUT,
        "Build call state for current function",
        -1
    )

    logger.debug("Action description:", action_desc)

    # Register the action
    res = ida_kernwin.register_action(action_desc)
    logger.debug("Register action result:", res)

    return res

def unregister_action():
    res = ida_kernwin.unregister_action(ACTION_NAME)
    logger.debug("Unregister action result:", res)

class my_hooks_t(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        logger.debug("Populating widget popup")
        widget_type = ida_kernwin.get_widget_type(widget)
        logger.debug(f"Widget type: {widget_type}")
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            logger.debug("Widget type is PSEUDOCODE")
            res = ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)
            logger.debug("Attach action to popup result:", res)

my_hooks = None

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