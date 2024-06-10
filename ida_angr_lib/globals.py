DO_NOTHING = 0
FIRST_ADDR = 0x444f0000
proj = None
mycc = None
cfg = None
phase = 1
simgr = None
state = None
driver_path = ""

eval_upto = 3
vulns_unique = set()
driver_info = {}
basic_info = {}
vulns_info = []
error_msgs = []


NPD_TARGETS = ['SystemBuffer', 'Type3InputBuffer', 'UserBuffer', 'ExAllocatePool_0x', 'ExAllocatePool2_0x', 'ExAllocatePool3_0x', 'ExAllocatePoolWithTag_0x', 'MmAllocateNonCachedMemory_0x', 'MmAllocateContiguousMemorySpecifyCache_0x']
SystemBuffer = None
Type3InputBuffer = None
UserBuffer = None
InputBufferLength = None
OutputBufferLength = None
IoControlCode = None

args = None

DOS_DEVICES = ['\\DosDevices\\'.encode('utf-16le'), '\\??\\'.encode('utf-16le')]
