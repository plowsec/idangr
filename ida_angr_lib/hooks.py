import angr

from ida_angr_lib.log import logger


class acrt_iob_func(angr.SimProcedure):
    def run(self, index):
        # Assuming the base address of the iob array is known
        iob_base = 0x1000  # This address is hypothetical
        iob_size = 0x100  # Size of each FILE structure, hypothetical

        # Calculate the address of the requested FILE structure
        file_struct_addr = iob_base + index * iob_size

        return file_struct_addr


class stdio_common_vfprintf(angr.SimProcedure):
    def run(self, options, stream, format, arg_list):
        # This is a simplified implementation
        # In reality, you would need to handle the format string and arguments

        # Read the format string from memory
        format_str = self.state.mem[format].string.concrete

        # Convert the concrete format string to a symbolic expression
        format_str_expr = self.state.solver.BVV(format_str + b'\n')

        # Write the symbolic expression to stdout
        self.state.posix.get_fd(1).write(format_str_expr, len(format_str) + 1)

        # Return the number of characters written
        return self.state.solver.BVV(len(format_str), self.state.arch.bits)


def opportunistically_eval_one(state, value, msg_on_multi):
    conc_vals = state.solver.eval_upto(value, 2)
    if len(conc_vals) > 1:
        print(msg_on_multi)
        print(f"Concretizing to {hex(conc_vals[0])}")
        state.solver.add(value == conc_vals[0])
    return conc_vals[0]


class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength

        conc_src_len = opportunistically_eval_one(
            self.state,
            src_len.resolved,
            f"Symbolic CopyUnicodeString source size...???? {src_unistr=} size={src_len=}")
        conc_dst_max_len = opportunistically_eval_one(
            self.state,
            dst_maxi_len.resolved,
            f"Symbolic CopyUnicodeString source maximum length...???? {dst_unistr=} size={dst_maxi_len=}")

        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved, min(conc_src_len, conc_dst_max_len))

        return 0

class HookKeEnterCriticalRegion(angr.SimProcedure):
    def run(self):
        logger.debug('HookKeEnterCriticalRegion called')
        return 0

class HookKeLeaveCriticalRegion(angr.SimProcedure):
    def run(self):
        logger.debug('HookKeLeaveCriticalRegion called')
        return 0

class HookZwClose(angr.SimProcedure):
    def run(self, Handle):
        logger.debug(f'HookZwClose called with Handle={Handle}')
        return 0

class HookObfDereferenceObject(angr.SimProcedure):
    def run(self, Object):
        logger.debug(f'HookObfDereferenceObject called with Object={Object}')
        return 0

class HookExAcquireResourceExclusiveLite(angr.SimProcedure):
    def run(self, Resource, Wait):
        logger.debug(f'HookExAcquireResourceExclusiveLite called with Resource={Resource}, Wait={Wait}')
        return 0


class HookRtlAppendUnicodeToString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        logger.debug(f'HookRtlAppendUnicodeToString called with DestinationString={DestinationString}, SourceString={SourceString}')

        try:
            # Resolve symbolic values for DestinationString and SourceString
            DestinationString = self._resolve_symbolic(DestinationString, "DestinationString")
            SourceString = self._resolve_symbolic(SourceString, "SourceString")

            if DestinationString is None or SourceString is None:
                logger.error('Failed to resolve DestinationString or SourceString')
                return self.state.solver.BVV(0xC0000001, 32)  # Return STATUS_UNSUCCESSFUL

            # Read the UNICODE_STRING structure from memory
            dest_unicode_string = self.state.mem[DestinationString].UNICODE_STRING

            # Extract and resolve the buffer pointer and lengths
            dest_buffer_ptr = self._resolve_symbolic(dest_unicode_string.Buffer, "Buffer")
            dest_length = self._resolve_symbolic(dest_unicode_string.Length, "Length")
            dest_max_length = self._resolve_symbolic(dest_unicode_string.MaximumLength, "MaximumLength")

            if dest_buffer_ptr is None or dest_length is None or dest_max_length is None:
                logger.error('Failed to resolve one or more fields in UNICODE_STRING')
                return self.state.solver.BVV(0xC0000001, 32)  # Return STATUS_UNSUCCESSFUL

            # Read the source string from memory
            src_string = self._read_wstring(SourceString)

            logger.debug(f'Destination buffer pointer: {dest_buffer_ptr}, Length: {dest_length}, MaximumLength: {dest_max_length}')
            logger.debug(f'Source string: {src_string}')

            # Calculate the length of the source string in bytes (UTF-16 encoding)
            src_length = len(src_string) * 2  # Each character is 2 bytes in UTF-16

            # Calculate the new length after appending
            new_length = dest_length + src_length

            # Check if the new length exceeds the maximum length
            if new_length > dest_max_length:
                logger.error('Destination buffer is not large enough to hold the appended string')
                return self.state.solver.BVV(0xC0000023, 32)  # Return STATUS_BUFFER_TOO_SMALL

            # Read the destination string from memory
            dest_string = self._read_wstring(dest_buffer_ptr)

            logger.debug(f'Destination string before append: {dest_string}')

            # Append the source string to the destination string
            appended_string = dest_string + src_string

            # Write the new string back to the destination buffer
            self.state.memory.store(dest_buffer_ptr, appended_string.encode('utf-16le'))

            # Update the length of the destination UNICODE_STRING
            self.state.mem[DestinationString].UNICODE_STRING.Length = new_length

            logger.debug(f'Appended string: {appended_string}')
            logger.debug(f'Updated destination length: {new_length}')

            return self.state.solver.BVV(0, 32)  # Return STATUS_SUCCESS

        except Exception as e:
            logger.error(f'Error in HookRtlAppendUnicodeToString: {e}')
            return self.state.solver.BVV(0xC0000001, 32)  # Return STATUS_UNSUCCESSFUL

    def _resolve_symbolic(self, value, name):
        """
        Helper function to resolve symbolic values to concrete values.
        """
        try:
            if isinstance(value, claripy.ast.Base):
                if self.state.solver.symbolic(value):
                    resolved_value = self.state.solver.eval(value, cast_to=int)
                    logger.debug(f'Resolved symbolic {name}: {resolved_value}')
                    return resolved_value
                return value.args[0] if value.args else value
            elif isinstance(value, angr.state_plugins.sim_action_object.SimActionObject):
                resolved_value = self.state.solver.eval(value.ast, cast_to=int)
                logger.debug(f'Resolved symbolic {name} from SimActionObject: {resolved_value}')
                return resolved_value
            elif isinstance(value, angr.state_plugins.view.SimMemView):
                resolved_value = self.state.solver.eval(value.concrete, cast_to=int)
                logger.debug(f'Resolved symbolic {name} from SimMemView: {resolved_value}')
                return resolved_value
            return value
        except Exception as e:
            logger.error(f'Error resolving symbolic value for {name}: {e}')
            return None

    def _read_wstring(self, address):
        """
        Helper function to read a wide string from memory.
        """
        try:
            wstring = self.state.mem[address].wstring.concrete
            return wstring
        except Exception as e:
            logger.error(f'Error reading wide string from address {address}: {e}')
            return ""

class HookRtlAppendUnicodeStringToString(angr.SimProcedure):
    def run(self, Destination, Source):
        logger.debug(f'HookRtlAppendUnicodeStringToString called with Destination={Destination}, Source={Source}')

        # Read the UNICODE_STRING structures from memory
        dest_unicode_string = self.state.mem[Destination].UNICODE_STRING
        src_unicode_string = self.state.mem[Source].UNICODE_STRING

        # Extract the buffer pointers and lengths
        dest_buffer_ptr = dest_unicode_string.Buffer
        dest_length = dest_unicode_string.Length
        dest_max_length = dest_unicode_string.MaximumLength

        src_buffer_ptr = src_unicode_string.Buffer
        src_length = src_unicode_string.Length

        logger.debug(
            f'Destination buffer pointer: {dest_buffer_ptr}, Length: {dest_length}, MaximumLength: {dest_max_length}')
        logger.debug(f'Source buffer pointer: {src_buffer_ptr}, Length: {src_length}')

        # Read the actual string data from memory
        dest_string = self.state.mem[dest_buffer_ptr].wstring.concrete
        src_string = self.state.mem[src_buffer_ptr].wstring.concrete

        logger.debug(f'Destination string: {dest_string}')
        logger.debug(f'Source string: {src_string}')

        # Calculate the new length after appending
        new_length = dest_length + src_length

        if new_length > dest_max_length:
            logger.error('Destination buffer is not large enough to hold the appended string')
            return self.state.solver.BVV(0, 32)  # Return an error code or handle the error appropriately

        # Append the source string to the destination string
        appended_string = dest_string + src_string

        # Write the new string back to the destination buffer
        self.state.memory.store(dest_buffer_ptr, appended_string.encode('utf-16le'))

        # Update the length of the destination UNICODE_STRING
        self.state.mem[Destination].UNICODE_STRING.Length = new_length

        logger.debug(f'Appended string: {appended_string}')
        logger.debug(f'Updated destination length: {new_length}')

        return self.state.solver.BVV(0, 32)  # Return success code (STATUS_SUCCESS)


# A more comprehensive mapping from NTSTATUS codes to DOS error codes
NTSTATUS_TO_DOS_ERROR = {
    0x00000000: 0,  # STATUS_SUCCESS -> ERROR_SUCCESS
    0xC0000001: 1,  # STATUS_UNSUCCESSFUL -> ERROR_INVALID_FUNCTION
    0xC0000002: 2,  # STATUS_NOT_IMPLEMENTED -> ERROR_FILE_NOT_FOUND
    0xC0000005: 5,  # STATUS_ACCESS_VIOLATION -> ERROR_ACCESS_DENIED
    0xC0000008: 6,  # STATUS_INVALID_HANDLE -> ERROR_INVALID_HANDLE
    0xC000000D: 87,  # STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER
    0xC0000022: 5,  # STATUS_ACCESS_DENIED -> ERROR_ACCESS_DENIED
    0xC0000034: 2,  # STATUS_OBJECT_NAME_NOT_FOUND -> ERROR_FILE_NOT_FOUND
    0xC0000035: 183,  # STATUS_OBJECT_NAME_COLLISION -> ERROR_ALREADY_EXISTS
    0xC000003A: 3,  # STATUS_OBJECT_PATH_NOT_FOUND -> ERROR_PATH_NOT_FOUND
    0xC000003B: 123,  # STATUS_OBJECT_PATH_SYNTAX_BAD -> ERROR_INVALID_NAME
    0xC0000043: 32,  # STATUS_SHARING_VIOLATION -> ERROR_SHARING_VIOLATION
    0xC000007B: 193,  # STATUS_INVALID_IMAGE_FORMAT -> ERROR_BAD_EXE_FORMAT
    0xC00000BB: 50,  # STATUS_NOT_SUPPORTED -> ERROR_NOT_SUPPORTED
    0xC00000F0: 1392,  # STATUS_FILE_CORRUPT_ERROR -> ERROR_FILE_CORRUPT
    0xC0000135: 126,  # STATUS_DLL_NOT_FOUND -> ERROR_MOD_NOT_FOUND
    0xC000013B: 1450,  # STATUS_INSUFFICIENT_RESOURCES -> ERROR_NO_SYSTEM_RESOURCES
    0xC0000142: 1114,  # STATUS_DLL_INIT_FAILED -> ERROR_DLL_INIT_FAILED
    0xC0000185: 1117,  # STATUS_IO_DEVICE_ERROR -> ERROR_IO_DEVICE
    0xC0000194: 1455,  # STATUS_NO_MEMORY -> ERROR_NOT_ENOUGH_MEMORY
    0xC0000202: 110,  # STATUS_PIPE_DISCONNECTED -> ERROR_BROKEN_PIPE
    0xC0000225: 1168,  # STATUS_NOT_FOUND -> ERROR_NOT_FOUND
    0xC0000226: 1169,  # STATUS_NOT_READY -> ERROR_NOT_READY
    0xC000025E: 31,  # STATUS_UNEXPECTED_IO_ERROR -> ERROR_GEN_FAILURE
    # Add more mappings as needed
}


class HookRtlNtStatusToDosErrorNoTeb(angr.SimProcedure):
    def run(self, Status):
        logger.debug(f'HookRtlNtStatusToDosErrorNoTeb called with Status={Status}')

        # Convert the NTSTATUS code to a DOS error code
        ntstatus = self.state.solver.eval(Status)
        dos_error = NTSTATUS_TO_DOS_ERROR.get(ntstatus, 31)  # Default to ERROR_GEN_FAILURE (31) if not found

        logger.debug(f'NTSTATUS: {ntstatus}, DOS Error: {dos_error}')

        return self.state.solver.BVV(dos_error, 32)


class HookIoIs32bitProcess(angr.SimProcedure):
    def run(self):
        logger.debug('HookIoIs32bitProcess called')
        return 0


class HookVsnprintf(angr.SimProcedure):
    def run(self, buffer, count, format, argptr):
        logger.debug(f'HookVsnprintf called with buffer={buffer}, count={count}, format={format}, argptr={argptr}')
        return 0


class HookExInitializeResourceLite(angr.SimProcedure):
    def run(self, Resource):
        logger.debug(f'HookExInitializeResourceLite called with Resource={Resource}')
        return 0


class HookExQueryDepthSList(angr.SimProcedure):
    def run(self, SListHead):
        logger.debug(f'HookExQueryDepthSList called with SListHead={SListHead}')
        return 0


class HookExpInterlockedPushEntrySList(angr.SimProcedure):
    def run(self, ListHead, ListEntry):
        logger.debug(f'HookExpInterlockedPushEntrySList called with ListHead={ListHead}, ListEntry={ListEntry}')
        return 0


class HookExpInterlockedPopEntrySList(angr.SimProcedure):
    def run(self, ListHead, Lock):
        logger.debug(f'HookExpInterlockedPopEntrySList called with ListHead={ListHead}, Lock={Lock}')
        return 0


class HookKeWaitForSingleObject(angr.SimProcedure):
    def run(self, Object, WaitReason, WaitMode, Alertable, Timeout):
        logger.debug(
            f'HookKeWaitForSingleObject called with Object={Object}, WaitReason={WaitReason}, WaitMode={WaitMode}, Alertable={Alertable}, Timeout={Timeout}')
        return 0


class HookRtlWriteRegistryValue(angr.SimProcedure):
    def run(self, RelativeTo, Path, ValueName, ValueType, ValueData, ValueLength):
        logger.debug(
            f'HookRtlWriteRegistryValue called with RelativeTo={RelativeTo}, Path={Path}, ValueName={ValueName}, ValueType={ValueType}, ValueData={ValueData}, ValueLength={ValueLength}')
        return 0


class HookIoGetDeviceProperty(angr.SimProcedure):
    def run(self, DeviceObject, DeviceProperty, BufferLength, PropertyBuffer, ResultLength):
        logger.debug(
            f'HookIoGetDeviceProperty called with DeviceObject={DeviceObject}, DeviceProperty={DeviceProperty}, BufferLength={BufferLength}, PropertyBuffer={PropertyBuffer}, ResultLength={ResultLength}')
        return 0


class HookKeReleaseMutex(angr.SimProcedure):
    def run(self, Mutex, Wait):
        logger.debug(f'HookKeReleaseMutex called with Mutex={Mutex}, Wait={Wait}')
        return 0

class HookSkIsSecureKernel(angr.SimProcedure):

    def run(self):
        logger.debug('HookSkIsSecureKernel called')
        return 0x0C0000002

class HookRtlGetVersion(angr.SimProcedure):
    # Hook RtlGetVersion to bypass version check.
    def run(self, lpVersionInformation):
        logger.debug(f'HookRtlGetVersion called with lpVersionInformation={lpVersionInformation}')
        ret_addr = hex(self.state.callstack.ret_addr)
        VersionInformation = self.state.mem[lpVersionInformation].struct._OSVERSIONINFOW
        dwMajorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMajorVersion = dwMajorVersion
        dwMinorVersion = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwMinorVersion = dwMinorVersion
        dwBuildNumber = claripy.BVS(f"RtlGetVersion_{ret_addr}", self.state.arch.bits // 2)
        VersionInformation.dwBuildNumber = dwBuildNumber
        return 0


class HookExGetPreviousMode(angr.SimProcedure):
    def run(self):
        logger.debug('HookExGetPreviousMode called')
        return 1


class HookKeQueryActiveGroupCount(angr.SimProcedure):
    def run(self):
        logger.debug('HookKeQueryActiveGroupCount called')
        return 1


class HookKeQueryActiveProcessors(angr.SimProcedure):
    def run(self):
        logger.debug('HookKeQueryActiveProcessors called')
        return 1


class HookKeQueryActiveProcessorCountEx(angr.SimProcedure):
    def run(self, GroupNumber):
        logger.debug(f'HookKeQueryActiveProcessorCountEx called with GroupNumber={GroupNumber}')
        return 1


class HookRtlIsNtDdiVersionAvailable(angr.SimProcedure):
    def run(self):
        logger.debug('HookRtlIsNtDdiVersionAvailable called')
        return 1


class HookExInterlockedPopEntrySList(angr.SimProcedure):
    def run(self, Resource):
        logger.debug(f'HookExInterlockedPopEntrySList called with Resource={Resource}')
        return 0


class HookPsGetVersion(angr.SimProcedure):
    # Hook PsGetVersion to bypass version check.
    def run(self, MajorVersion, MinorVersion, BuildNumber, CSDVersion):
        logger.debug(
            f'HookPsGetVersion called with MajorVersion={MajorVersion}, MinorVersion={MinorVersion}, BuildNumber={BuildNumber}, CSDVersion={CSDVersion}')
        ret_addr = hex(self.state.callstack.ret_addr)
        major_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MajorVersion, major_version, self.state.arch.bytes,
                                endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        minor_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(MinorVersion, minor_version, self.state.arch.bytes,
                                endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        build_number = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(BuildNumber, build_number, self.state.arch.bytes,
                                endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        csd_version = claripy.BVS(f"PsGetVersion_{ret_addr}", self.state.arch.bits * 2)
        self.state.memory.store(CSDVersion, csd_version, self.state.arch.bytes * 2,
                                endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 0


class HookZwQueryInformationProcess(angr.SimProcedure):
    def run(self, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
        logger.debug(
            f'HookZwQueryInformationProcess called with ProcessHandle={ProcessHandle}, ProcessInformationClass={ProcessInformationClass}, ProcessInformation={ProcessInformation}, ProcessInformationLength={ProcessInformationLength}, ReturnLength={ReturnLength}')
        if not ProcessInformationLength.symbolic and self.state.solver.eval(ProcessInformationLength) == 0:
            return 0xC0000004
        return 0


class HookDoNothing(angr.SimProcedure):
    def run(self):
        logger.debug('HookDoNothing called')
        return 0


class HookFltGetRoutineAddress(angr.SimProcedure):
    # Return the function address acquired by FltGetRoutineAddress.
    def run(self, FltMgrRoutineName):
        logger.debug(f'HookFltGetRoutineAddress called with FltMgrRoutineName={FltMgrRoutineName}')
        return 0


class HookProbeForRead(angr.SimProcedure):
    # Tag the tainted buffer that is validated with ProbeForRead.
    def run(self, Address, Length, Alignment):
        logger.debug(f'HookProbeForRead called with Address={Address}, Length={Length}, Alignment={Alignment}')



class HookProbeForWrite(angr.SimProcedure):
    # Tag the tainted buffer that is validated with ProbeForWrite.
    def run(self, Address, Length, Alignment):
        logger.debug(f'HookProbeForWrite called with Address={Address}, Length={Length}, Alignment={Alignment}')

class HookMmIsAddressValid(angr.SimProcedure):
    # Tag the tainted buffer that is validated with MmIsAddressValid.
    def run(self, VirtualAddress):
        logger.debug(f'HookMmIsAddressValid called with VirtualAddress={VirtualAddress}')

        return 1


class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        logger.debug(
            f'HookZwOpenSection called with SectionHandle={SectionHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}')
        ret_addr = hex(self.state.callstack.ret_addr)

        # Trace the handle opened by ZwOpenSection.
        handle = claripy.BVS(f'ZwOpenSection_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(SectionHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness,
                                disable_actions=True, inspect=False)

        # Get the object name.
        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            return 0

        # Store the handle and object name.
        self.state.globals['open_section_handles'] += ((handle, object_name),)
        return 0


class HookRtlInitUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        logger.debug(
            f'HookRtlInitUnicodeString called with DestinationString={DestinationString}, SourceString={SourceString}')
        ret_addr = hex(self.state.callstack.ret_addr)

        # Resolve the SourceString.
        try:
            if SourceString.symbolic:
                raise
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS(f"RtlInitUnicodeString_{ret_addr}", 8 * 10), claripy.BVV(0, 16))

        # Initalize the DestinationString.
        byte_length = string_orig.length // 8
        new_buffer = utils.next_base_addr()
        self.state.memory.store(new_buffer, string_orig, byte_length, disable_actions=True, inspect=False)
        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size), unistr._type.size // 8,
                                disable_actions=True, inspect=False)
        unistr.Length = byte_length - 2
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # Store the unicode string if it is tainted.
        if (not SourceString.symbolic and utils.tainted_buffer(
                self.state.memory.load(SourceString, 0x10, disable_actions=True,
                                       inspect=False))) or utils.tainted_buffer(SourceString) or str(SourceString) in \
                self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(unistr.Buffer.resolved),)

        return 0


class HookRtlCopyUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        logger.debug(
            f'HookRtlCopyUnicodeString called with DestinationString={DestinationString}, SourceString={SourceString}')
        # Restrict the length of the unicode string.
        src_unistr = self.state.mem[SourceString].struct._UNICODE_STRING
        src_len = src_unistr.Length
        conc_src_len = self.state.solver.min(src_len.resolved)
        self.state.solver.add(src_len.resolved == conc_src_len)

        dst_unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        dst_maxi_len = src_unistr.MaximumLength
        conc_dst_max_len = self.state.solver.min(dst_maxi_len.resolved)
        self.state.solver.add(dst_maxi_len.resolved == conc_dst_max_len)

        # Copy the unicode string.
        memcpy = angr.procedures.SIM_PROCEDURES['libc']['memcpy']
        self.inline_call(memcpy, dst_unistr.Buffer.resolved, src_unistr.Buffer.resolved,
                         min(conc_src_len, conc_dst_max_len))

        # Store the unicode string if it is tainted.
        if utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(dst_unistr.Buffer.resolved),)

        return 0


class HookExAllocatePool(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool.
    def run(self, PoolType, NumberOfBytes):
        logger.debug(f'HookExAllocatePool called with PoolType={PoolType}, NumberOfBytes={NumberOfBytes}')
        if globals.phase == 2:
            ret_addr = hex(self.state.callstack.ret_addr)
            allocated_ptr = claripy.BVS(f"ExAllocatePool_{ret_addr}", self.state.arch.bits)
            return allocated_ptr
        else:
            return utils.next_base_addr()


class HookExAllocatePool2(angr.SimProcedure):
    def run(self, Flags, NumberOfBytes, Tag):
        logger.debug(f'HookExAllocatePool2 called with Flags={Flags}, NumberOfBytes={NumberOfBytes}, Tag={Tag}')
        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"ExAllocatePool2_{ret_addr}", self.state.arch.bits)

        # Add constraints to ensure the allocated pointer is within a valid pool range
        # Example ranges for Windows kernel pools
        nonpaged_pool_min = 0xfffff80000000000
        nonpaged_pool_max = 0xffffffffffffffff
        paged_pool_min = 0xfffff98000000000
        paged_pool_max = 0xfffffa8000000000

        # Constrain the allocated pointer to be within either the nonpaged or paged pool ranges
        self.state.solver.add(
            claripy.Or(
                claripy.And(allocated_ptr >= nonpaged_pool_min, allocated_ptr <= nonpaged_pool_max),
                claripy.And(allocated_ptr >= paged_pool_min, allocated_ptr <= paged_pool_max)
            )
        )

        logger.debug(f"Allocated pointer: {allocated_ptr}")
        return allocated_ptr


class HookExAllocatePool3(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePool3.
    def run(self, Flags, NumberOfBytes, Tag, ExtendedParameters, ExtendedParametersCount):
        logger.debug(
            f'HookExAllocatePool3 called with Flags={Flags}, NumberOfBytes={NumberOfBytes}, Tag={Tag}, ExtendedParameters={ExtendedParameters}, ExtendedParametersCount={ExtendedParametersCount}')
    
        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"ExAllocatePool3_{ret_addr}", self.state.arch.bits)
        return allocated_ptr
    
    


class HookExAllocatePoolWithTag(angr.SimProcedure):
    # Trace the allocated buffer by ExAllocatePoolWithTag.
    def run(self, PoolType, NumberOfBytes, Tag):
        logger.debug(
            f'HookExAllocatePoolWithTag called with PoolType={PoolType}, NumberOfBytes={NumberOfBytes}, Tag={Tag}')

        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"ExAllocatePoolWithTag_{ret_addr}", self.state.arch.bits)
        return allocated_ptr


class HookFreePoolWithTag(angr.SimProcedure):

    def run(self, Pool, Tag):
        logger.debug(f'HookFreePoolWithTag called with Pool={Pool}, Tag={Tag}')

class HookSkFreePool(angr.SimProcedure):

    def run(self, Pool):
        logger.debug(f'HookSkFreePool called with Pool={Pool}')

class HookSkAllocatePool(angr.SimProcedure):

    def run(self, Flags, NumberOfBytes, Tag):
        logger.debug(f'HookExAllocatePool2 called with Flags={Flags}, NumberOfBytes={NumberOfBytes}, Tag={Tag}')

        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"ExAllocatePool2_{ret_addr}", self.state.arch.bits)
        return allocated_ptr


class HookMmAllocateNonCachedMemory(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateNonCachedMemory.
    def run(self, NumberOfBytes):
        logger.debug(f'HookMmAllocateNonCachedMemory called with NumberOfBytes={NumberOfBytes}')

        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"MmAllocateNonCachedMemory_{ret_addr}", self.state.arch.bits)
        return allocated_ptr



class HookMmAllocateContiguousMemorySpecifyCache(angr.SimProcedure):
    # Trace the allocated buffer by MmAllocateContiguousMemorySpecifyCache.
    def run(self, NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, CacheType):
        logger.debug(
        f'HookMmAllocateContiguousMemorySpecifyCache called with NumberOfBytes={NumberOfBytes}, LowestAcceptableAddress={LowestAcceptableAddress}, Highest AcceptableAddress={HighestAcceptableAddress}, BoundaryAddressMultiple={BoundaryAddressMultiple}, CacheType={CacheType}')
        ret_addr = hex(self.state.callstack.ret_addr)
        allocated_ptr = claripy.BVS(f"MmAllocateContiguousMemorySpecifyCache_{ret_addr}", self.state.arch.bits)
        return allocated_ptr



class HookObReferenceObjectByHandle(angr.SimProcedure):
    # Trace the handle opened by ObReferenceObjectByHandle.
    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        logger.debug(f'HookObReferenceObjectByHandle called with Handle={Handle}, DesiredAccess={DesiredAccess}, ObjectType={ObjectType}, AccessMode={AccessMode}, Object={Object}, HandleInformation={HandleInformation}')
        ret_addr = hex(self.state.callstack.ret_addr)
        object = claripy.BVS(f"ObReferenceObjectByHandle_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(Object, object, self.state.arch.bytes, endness=self.state.arch.memory_endness,
                                disable_actions=True, inspect=False)
        return 0


class HookMmMapIoSpace(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, MEMORY_CACHING_TYPE):
        logger.debug(f'HookMmMapIoSpace called with PhysicalAddress={PhysicalAddress}, NumberOfBytes={NumberOfBytes}, MEMORY_CACHING_TYPE={MEMORY_CACHING_TYPE}')

        return utils.next_base_addr()


class HookMmMapIoSpaceEx(angr.SimProcedure):
    def run(self, PhysicalAddress, NumberOfBytes, Protect):
        logger.debug(f'HookMmMapIoSpaceEx called with PhysicalAddress={PhysicalAddress}, NumberOfBytes={NumberOfBytes}, Protect={Protect}')

        return utils.next_base_addr()


class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
        logger.debug(f'HookHalTranslateBusAddress called with InterfaceType={InterfaceType}, BusNumber={BusNumber}, BusAddress={BusAddress}, AddressSpace={AddressSpace}, TranslatedAddress={TranslatedAddress}')
        self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, self.state.arch.bytes,
                                endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 1


class HookZwMapViewOfSection(angr.SimProcedure):
    def run(self, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect):
        logger.debug(f'HookZwMapViewOfSection called with SectionHandle={SectionHandle}, ProcessHandle={ProcessHandle}, BaseAddress={BaseAddress}, ZeroBits={ZeroBits}, CommitSize={CommitSize}, SectionOffset={SectionOffset}, ViewSize={ViewSize}, InheritDisposition={InheritDisposition}, AllocationType={AllocationType}, Win32Protect={Win32Protect}')

        return 0


class HookZwOpenProcess(angr.SimProcedure):
    def run(self, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
        logger.debug(f'HookZwOpenProcess called with ProcessHandle={ProcessHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, ClientId={ClientId}')

        return 0


class HookPsLookupProcessByProcessId(angr.SimProcedure):
    def run(self, ProcessId, Process):
        logger.debug(f'HookPsLookupProcessByProcessId called with ProcessId={ProcessId}, Process={Process}')

        return 0


class HookObOpenObjectByPointer(angr.SimProcedure):
    def run(self, Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, Handle):
        logger.debug(f'HookObOpenObjectByPointer called with Object={Object}, HandleAttributes={HandleAttributes}, PassedAccessState={PassedAccessState}, DesiredAccess={DesiredAccess}, ObjectType={ObjectType}, AccessMode={AccessMode}, Handle={Handle}')
        # HandleAttributes is not OBJ_FORCE_ACCESS_CHECK.
        tmp_state = self.state.copy()
        tmp_state.solver.add(HandleAttributes & 1024 == 0)

        # Check if we can control the parameters of ObOpenObjectByPointer.
        if tmp_state.satisfiable() and str(Object) in self.state.globals['tainted_eprocess']:
            ret_addr = hex(self.state.callstack.ret_addr)
            utils.print_vuln('controllable process handle', 'ObOpenObjectByPointer - Object controllable',
                                self.state, {'Object': str(Object), 'Handle': str(Handle)},
                                {'return address': ret_addr})
        return 0


class HookMemcpy(angr.SimProcedure):
    def run(self, dest, src, size):
        logger.debug(f'HookMemcpy called with dest={dest}, src={src}, size={size}')
        """
        ret_addr = hex(self.state.callstack.ret_addr)
        dest_asts = [i for i in dest.recursive_children_asts]
        dest_base = dest_asts[0] if len(dest_asts) > 1 else dest
        dest_vars = dest.variables

        src_asts = [i for i in src.recursive_children_asts]
        src_base = src_asts[0] if len(src_asts) > 1 else src
        src_vars = src.variables

        # Check whether the src or dest address can be controlled.
        if ('*' in str(dest) and utils.tainted_buffer(dest) and str(dest_base) not in self.state.globals[
            'tainted_ProbeForWrite'] and len(dest_vars) == 1) or (
                '*' in str(src) and utils.tainted_buffer(src) and str(src_base) not in self.state.globals[
            'tainted_ProbeForRead'] and len(src_vars) == 1):
            utils.print_vuln('dest or src controllable', 'memcpy/memmove', self.state,
                             {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': ret_addr})

        # Buffer overflow detected if the size can be controlled and the destination address is not symbolic to avoid false positive.
        tmp_state = self.state.copy()
        tmp_state.solver.add(size == 0x10000000)
        if utils.tainted_buffer(size) and tmp_state.satisfiable() and not dest.symbolic:
            utils.print_vuln('buffer overflow', 'memcpy/memmove', self.state,
                             {'dest': str(dest), 'src': str(src), 'size': str(size)}, {'return address': ret_addr})

        # Call original memcpy after analysis.
        size_min = self.state.solver.min(size)
        if size_min > 0x1000:
            size_min = 0x1000
        elif size.symbolic and size_min < 0x10:
            tmp_state = self.state.copy()
            tmp_state.solver.add(size == 0x10)
            if tmp_state.satisfiable():
                size_min = 0x10
        """

        angr.procedures.SIM_PROCEDURES['libc']['memcpy'](cc=self.cc).execute(self.state,
                                                                             arguments=(dest, src, size))

        return 0


class HookZwDeleteFile(angr.SimProcedure):
    def run(self, ObjectAttributes):
        logger.debug(f'HookZwDeleteFile called with ObjectAttributes={ObjectAttributes}')
        if globals.phase == 2:
            # Check if we can control the parameters of ZwDeleteFile.
            utils.analyze_ObjectAttributes('ZwDeleteFile', self.state, ObjectAttributes)

        return 0


class HookZwOpenFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
        logger.debug(f'HookZwOpenFile called with FileHandle={FileHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, IoStatusBlock={IoStatusBlock}, ShareAccess={ShareAccess}, OpenOptions={OpenOptions}')
        if globals.phase == 2:
            # Check if we can control the parameters of ZwOpenFile.
            utils.analyze_ObjectAttributes('ZwOpenFile', self.state, ObjectAttributes)

        return 0


class HookZwCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
            ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
        logger.debug(f'HookZwCreateFile called with FileHandle={FileHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, IoStatusBlock={IoStatusBlock}, AllocationSize={AllocationSize}, FileAttributes={FileAttributes}, ShareAccess={ShareAccess}, CreateDisposition={CreateDisposition}, CreateOptions={CreateOptions}, EaBuffer={EaBuffer}, EaLength={EaLength}')
        if globals.phase == 2:
            # Check if we can control the parameters of ZwCreateFile.
            utils.analyze_ObjectAttributes('ZwCreateFile', self.state, ObjectAttributes)

        return 0


class HookZwWriteFile(angr.SimProcedure):
    def run(self, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key):
        logger.debug(f'HookZwWriteFile called with FileHandle={FileHandle}, Event={Event}, ApcRoutine={ApcRoutine}, ApcContext={ApcContext}, IoStatusBlock={IoStatusBlock}, Buffer={Buffer}, Length={Length}, ByteOffset={ByteOffset}, Key={Key}')
        return 0


class HookIoCreateFile(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
            ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options):
        logger.debug(f'HookIoCreateFile called with FileHandle={FileHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, IoStatusBlock={IoStatusBlock}, AllocationSize={AllocationSize}, FileAttributes={FileAttributes}, ShareAccess={ShareAccess}, Disposition={Disposition}, CreateOptions={CreateOptions}, EaBuffer={EaBuffer}, EaLength={EaLength}, CreateFileType={CreateFileType}, InternalParameters={InternalParameters}, Options={Options}')
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFile.
            utils.analyze_ObjectAttributes('IoCreateFile', self.state, ObjectAttributes)

        return 0


class HookIoCreateFileEx(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
            ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options,
            DriverContext):
        logger.debug(f'HookIoCreateFileEx called with FileHandle={FileHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, IoStatusBlock={IoStatusBlock}, AllocationSize={AllocationSize}, FileAttributes={FileAttributes}, ShareAccess={ShareAccess}, Disposition={Disposition}, CreateOptions={CreateOptions}, EaBuffer={EaBuffer}, EaLength={EaLength}, CreateFileType={CreateFileType}, InternalParameters={InternalParameters}, Options={Options}, DriverContext={DriverContext}')
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileEx.
            utils.analyze_ObjectAttributes('IoCreateFileEx', self.state, ObjectAttributes)

        return 0


class HookIoCreateFileSpecifyDeviceObjectHint(angr.SimProcedure):
    def run(self, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
            ShareAccess, Disposition, CreateOptions, EaBuffer, EaLength, CreateFileType, InternalParameters, Options,
            DeviceObject):
        logger.debug(f'HookIoCreateFileSpecifyDeviceObjectHint called with FileHandle={FileHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, IoStatusBlock={IoStatusBlock}, AllocationSize={AllocationSize}, FileAttributes={FileAttributes}, ShareAccess={ShareAccess}, Disposition={Disposition}, CreateOptions={CreateOptions}, EaBuffer={EaBuffer}, EaLength={EaLength}, CreateFileType={CreateFileType}, InternalParameters={InternalParameters}, Options={Options}, DeviceObject={DeviceObject}')
        if globals.phase == 2:
            # Check if we can control the parameters of IoCreateFileSpecifyDeviceObjectHint.
            utils.analyze_ObjectAttributes('IoCreateFileSpecifyDeviceObjectHint', self.state, ObjectAttributes)

        return 0


class HookZwQueryInformationFile(angr.SimProcedure):
    def run(self, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
        logger.debug(f'HookZwQueryInformationFile called with FileHandle={FileHandle}, IoStatusBlock={IoStatusBlock}, FileInformation={FileInformation}, Length={Length}, FileInformationClass={FileInformationClass}')
        ret_addr = hex(self.state.callstack.ret_addr)
        isb = self.state.mem[IoStatusBlock].struct._IO_STATUS_BLOCK
        isb.u.Status = 0
        isb.Information = utils.next_base_addr()
        if self.state.solver.eval(FileInformationClass) == 9:
            fi = self.state.mem[FileInformation].struct._FILE_NAME_INFORMATION
            fi.FileNameLength = 0x10
        return 0


class HookZwCreateKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition):
        logger.debug(f'HookZwCreateKey called with KeyHandle={KeyHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}, TitleIndex={TitleIndex}, Class={Class}, CreateOptions={CreateOptions}, Disposition={Disposition}')
        return 0


class HookZwOpenKey(angr.SimProcedure):
    def run(self, KeyHandle, DesiredAccess, ObjectAttributes):
        logger.debug(f'HookZwOpenKey called with KeyHandle={KeyHandle}, DesiredAccess={DesiredAccess}, ObjectAttributes={ObjectAttributes}')
        utils.analyze_ObjectAttributes('ZwOpenKey', self.state, ObjectAttributes)

        return 0


class HookZwDeleteValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName):
        logger.debug(f'HookZwDeleteValueKey called with KeyHandle={KeyHandle}, ValueName={ValueName}')
        return 0


class HookZwQueryValueKey(angr.SimProcedure):
    def run(self, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
        logger.debug(f'HookZwQueryValueKey called with KeyHandle={KeyHandle}, ValueName={ValueName}, KeyValueInformationClass={KeyValueInformationClass}, KeyValueInformation={KeyValueInformation}, Length={Length}, ResultLength={ResultLength}')
        return 0


class HookNdisRegisterProtocolDriver(angr.SimProcedure):
    def run(self, ProtocolDriverContext, ProtocolCharacteristics, NdisProtocolHandle):
        logger.debug(f'HookNdisRegisterProtocolDriver called with ProtocolDriverContext={ProtocolDriverContext}, ProtocolCharacteristics={ProtocolCharacteristics}, NdisProtocolHandle={NdisProtocolHandle}')
        self.state.memory.store(NdisProtocolHandle, 0x87, self.state.arch.bytes, endness=self.state.arch.memory_endness,
                                disable_actions=True, inspect=False)
        return 0



def set_all_hooks(proj, hooked_addresses, mycc):


    hook_dict = {
    
        'RtlAppendUnicodeToString': HookRtlAppendUnicodeToString(cc=mycc),
        'RtlNtStatusToDosErrorNoTeb': HookRtlNtStatusToDosErrorNoTeb(cc=mycc),
        'ObReferenceObjectByHandle': HookObReferenceObjectByHandle(cc=mycc),
        'ObfDereferenceObject': HookObfDereferenceObject(cc=mycc),
        'ZwClose': HookZwClose(cc=mycc),
        'ZwOpenSection': HookZwOpenSection(cc=mycc),
        'RtlInitUnicodeString': HookRtlInitUnicodeString(cc=mycc),
        'RtlCopyUnicodeString': HookRtlCopyUnicodeString(cc=mycc),
        'IoIs32bitProcess': HookIoIs32bitProcess(cc=mycc),
        'RtlGetVersion': HookRtlGetVersion(cc=mycc),
        'ExGetPreviousMode': HookExGetPreviousMode(cc=mycc),
        'KeQueryActiveGroupCount': HookKeQueryActiveGroupCount(cc=mycc),
        'KeQueryActiveProcessors': HookKeQueryActiveProcessors(cc=mycc),
        'KeQueryActiveProcessorCountEx': HookKeQueryActiveProcessorCountEx(cc=mycc),
        'ExInterlockedPopEntrySList': HookExInterlockedPopEntrySList(cc=mycc),
        'ExQueryDepthSList': HookExQueryDepthSList(cc=mycc),
        'ExpInterlockedPushEntrySList': HookExpInterlockedPushEntrySList(cc=mycc),
        'ExpInterlockedPopEntrySList': HookExpInterlockedPopEntrySList(cc=mycc),
        'PsGetVersion': HookPsGetVersion(cc=mycc),
        'ExInitializeResourceLite': HookExInitializeResourceLite(cc=mycc),
        'KeWaitForSingleObject': HookKeWaitForSingleObject(cc=mycc),
        'RtlWriteRegistryValue': HookRtlWriteRegistryValue(cc=mycc),
        'IoGetDeviceProperty': HookIoGetDeviceProperty(cc=mycc),
        'KeReleaseMutex': HookKeReleaseMutex(cc=mycc),
        #'MmGetSystemRoutineAddress': HookMmGetSystemRoutineAddress(cc=mycc),
        'FltGetRoutineAddress': HookFltGetRoutineAddress(cc=mycc),
        'RtlGetElementGenericTable': HookDoNothing(cc=mycc),
        'ExAcquireResourceExclusiveLite': HookDoNothing(cc=mycc),
        'ProbeForRead': HookProbeForRead(cc=mycc),
        'ProbeForWrite': HookProbeForWrite(cc=mycc),
        'MmIsAddressValid': HookMmIsAddressValid(cc=mycc),
        'ZwQueryInformationFile': HookZwQueryInformationFile(cc=mycc),
        'ZwQueryInformationProcess': HookZwQueryInformationProcess(cc=mycc),
        'ZwWriteFile': HookZwWriteFile(cc=mycc),
        'ZwCreateKey': HookZwCreateKey(cc=mycc),
        'ZwOpenKey': HookZwOpenKey(cc=mycc),
        'ZwDeleteValueKey': HookZwDeleteValueKey(cc=mycc),
        'ZwQueryValueKey': HookZwQueryValueKey(cc=mycc),
        'NdisRegisterProtocolDriver': HookNdisRegisterProtocolDriver(cc=mycc),
        'ExAllocatePool': HookExAllocatePool(cc=mycc),
        'ExAllocatePool2': angr.procedures.SIM_PROCEDURES['libc']['malloc'](cc=mycc),
        'ExAllocatePool3': HookExAllocatePool3(cc=mycc),
        'MmAllocateNonCachedMemory': HookMmAllocateNonCachedMemory(cc=mycc),
        'ExAllocatePoolWithTag': HookExAllocatePoolWithTag(cc=mycc),
        'MmAllocateContiguousMemorySpecifyCache': HookMmAllocateContiguousMemorySpecifyCache(cc=mycc),
        'MmMapIoSpace': HookMmMapIoSpace(cc=mycc),
        'MmMapIoSpaceEx': HookMmMapIoSpaceEx(cc=mycc),
        'HalTranslateBusAddress': HookHalTranslateBusAddress(cc=mycc),
        'ZwMapViewOfSection': HookZwMapViewOfSection(cc=mycc),
        'ZwOpenProcess': HookZwOpenProcess(cc=mycc),
        'PsLookupProcessByProcessId': HookPsLookupProcessByProcessId(cc=mycc),
        'ObOpenObjectByPointer': HookObOpenObjectByPointer(cc=mycc),
        'ZwDeleteFile': HookZwDeleteFile(cc=mycc),
        'ZwOpenFile': HookZwOpenFile(cc=mycc),
        'ZwCreateFile': HookZwCreateFile(cc=mycc),
        'IoCreateFile': HookIoCreateFile(cc=mycc),
        'IoCreateFileEx': HookIoCreateFileEx(cc=mycc),
        'IoCreateFileSpecifyDeviceObjectHint': HookIoCreateFileSpecifyDeviceObjectHint(cc=mycc),
        'ExFreePoolWithTag': HookFreePoolWithTag(cc=mycc),
        'SkAllocatePool': HookSkAllocatePool(cc=mycc),
        'SkIsSecureKernel': HookSkIsSecureKernel(cc=mycc),
        'SkFreePool': HookSkFreePool(cc=mycc),
        'RtlAppendUnicodeStringToString': HookRtlAppendUnicodeStringToString(cc=mycc),
        'KeEnterCriticalRegion': HookKeEnterCriticalRegion(cc=mycc),
        'KeLeaveCriticalRegion': HookKeLeaveCriticalRegion(cc=mycc),
        'ExAcquireResourceExclusiveLite': HookExAcquireResourceExclusiveLite(cc=mycc),
    }

    for func_name, hook_impl in hook_dict.items():
        hook_address = proj.hook_symbol(func_name, hook_impl)
        if hook_address is not None:
            hooked_addresses.append(hook_address)
