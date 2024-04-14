import gdb

# class SigtrapHandler(gdb.Breakpoint):
    # def __init__(self):
    #     super().__init__("sigtrap")
    
    # def stop(self):
    #     pc = gdb.parse_and_eval("$pc")
    #     print("PC value:", pc)
    #     gdb.execute("continue")
    #     return False

# SigtrapHandler()

# with open("trace.log", "w") as f:
#     gdb.execute("continue")

# def signal_stop_handler(event):
#     if isinstance(event, gdb.StopEvent):
#         print(f"event type: stop: {event}")
#         current_pc = gdb.selected_frame().read_register("pc")
#         current_r0 = gdb.selected_frame().read_register("r0")
#         print(f"current pc is: {current_pc}, current r0 is {hex(current_r0)}")
#         # gdb.execute("continue")
#     # if isinstance(event, gdb.SignalEvent):
#     #     print("stop reason: signal")
#     #     print("stop signal: %s" % (event.stop_signal))
#     #     if event.inferior_thread is not None:
#     #         print("thread num: %s" % (event.inferior_thread.num))


# def breakpoint_stop_handler(event):
#     if isinstance(event, gdb.StopEvent):
#         print(f"[breakpoint_stop_handler]: event type: stop: {event}")
#         current_pc = gdb.selected_frame().read_register("pc")
#         current_r0 = gdb.selected_frame().read_register("r0")
#         print(f"current pc is: {current_pc}, current r0 is {hex(current_r0)}")
#         gdb.execute("continue")
#     if isinstance(event, gdb.BreakpointEvent):
#         print("stop reason: breakpoint")
#         print("first breakpoint number: %s" % (event.breakpoint.number))
#         for bp in event.breakpoints:
#             print("breakpoint number: %s" % (bp.number))
#         if event.inferior_thread is not None:
#             print("thread num: %s" % (event.inferior_thread.num))
#         else:
#             print("all threads stopped")


# def exit_handler(event):
#     assert isinstance(event, gdb.ExitedEvent)
#     print("event type: exit")
#     if hasattr(event, "exit_code"):
#         print("exit code: %d" % (event.exit_code))
#     else:
#         print("exit code: not-present")
#     print("exit inf: %d" % (event.inferior.num))
#     print("exit pid: %d" % (event.inferior.pid))
#     print("dir ok: %s" % str("exit_code" in dir(event)))


# def continue_handler(event):
#     assert isinstance(event, gdb.ContinueEvent)
#     print("event type: continue")
#     if event.inferior_thread is not None:
#         print("thread num: %s" % (event.inferior_thread.num))


# def new_objfile_handler(event):
#     assert isinstance(event, gdb.NewObjFileEvent)
#     print("event type: new_objfile")
#     print("new objfile name: %s" % (event.new_objfile.filename))


# def clear_objfiles_handler(event):
#     assert isinstance(event, gdb.ClearObjFilesEvent)
#     print("event type: clear_objfiles")
#     print("progspace: %s" % (event.progspace.filename))


# def inferior_call_handler(event):
#     if isinstance(event, gdb.InferiorCallPreEvent):
#         print("event type: pre-call")
#     elif isinstance(event, gdb.InferiorCallPostEvent):
#         print("event type: post-call")
#     else:
#         assert False
#     print("ptid: %s" % (event.ptid,))
#     print("address: 0x%x" % (event.address))


# def register_changed_handler(event):
#     assert isinstance(event, gdb.RegisterChangedEvent)
#     print("event type: register-changed")
#     assert isinstance(event.frame, gdb.Frame)
#     print("frame: %s" % (event.frame))
#     print("num: %s" % (event.regnum))


# def memory_changed_handler(event):
#     assert isinstance(event, gdb.MemoryChangedEvent)
#     print("event type: memory-changed")
#     print("address: %s" % (event.address))
#     print("length: %s" % (event.length))


# class test_events(gdb.Command):
#     """Test events."""

#     def __init__(self):
#         gdb.Command.__init__(self, "test-events", gdb.COMMAND_STACK)

#     def invoke(self, arg, from_tty):
#         gdb.events.stop.connect(signal_stop_handler)
#         # gdb.events.stop.connect(breakpoint_stop_handler)
#         # gdb.events.exited.connect(exit_handler)
#         # gdb.events.cont.connect(continue_handler)
#         # gdb.events.inferior_call.connect(inferior_call_handler)
#         # gdb.events.memory_changed.connect(memory_changed_handler)
#         # gdb.events.register_changed.connect(register_changed_handler)
#         print("Event testers registered.")

# gdb.execute("monitor reset halt")

# # test_events()  

# # gdb.events.stop.connect(signal_stop_handler)
# gdb.events.stop.connect(breakpoint_stop_handler)

# get the folder of src and apppend to GDB's python interpreter's path
import os
dir_path = os.path.dirname(os.path.realpath(__file__))
os.sys.path.append(dir_path)
from hwb import loop_ends, hwb

class MyBreakpointFunc(gdb.Function):
    """Return the value of a calling function's variable.

    Usage: $_caller_var (NAME [, NUMBER-OF-FRAMES [, DEFAULT-VALUE]])

    Arguments:

      NAME: The name of the variable.

      NUMBER-OF-FRAMES: How many stack frames to traverse back from the currently
        selected frame to compare with.
        The default is 1.

      DEFAULT-VALUE: Return value if the variable can't be found.
        The default is 0.

    Returns:
      The value of the variable in the specified frame, DEFAULT-VALUE if the
      variable can't be found."""

    def __init__(self, log_file=dir_path+"/../binaries/pc_trace.log", end_addr=None):
        super(MyBreakpointFunc, self).__init__("my_bp_func")
        self.end_addr = end_addr
        self.log_file = log_file
        self.line_buffer = []

    def invoke(self):
        current_pc = gdb.selected_frame().read_register("pc")
        current_r0 = gdb.selected_frame().read_register("r0")
        self.line_buffer.append(f"current_pc: {current_pc} current_r0: {hex(current_r0)}\n")
        print(f"current_pc: {current_pc} current_r0: {hex(current_r0)}")
        if current_r0 in self.end_addr:
            with open(self.log_file, "w") as f:
                f.writelines(self.line_buffer)
            return False
        else:
            print(f"ERROR: unexpected exception from {hex(current_r0)}")
            return True


MyBreakpointFunc(end_addr=loop_ends)

gdb.execute(f"b *{hex(hwb)} if $my_bp_func()")
gdb.execute("monitor reset halt")
