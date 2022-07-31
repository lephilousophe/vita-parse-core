import gzip

from elftools.elf.elffile import ELFFile

from sys import argv
from collections import defaultdict

from indent import indent, iprint

from construct import *

class VFlagsEnum(FlagsEnum):
    def _decode(self, obj, context, path):
        obj2 = super()._decode(obj, context, path)
        obj2._flagsvalue = obj
        return obj2

Tid = Hex(Int32ul)
PidTid = Struct(
        "pid" / Hex(Int32ul),
        "tid" / Hex(Int32ul))

PROCESS_ATTR = {
    'PROCESS_ATTR_LOADED': 0x1,
    'PROCESS_ATTR_DEBUG_STATE': 0x2,
    'PROCESS_ATTR_SYSTEM': 0x4,
    'PROCESS_ATTR_SUSPENDED': 0x8,
    'PROCESS_ATTR_DEBUGGABLE': 0x10000,
    'PROCESS_ATTR_ATTACHED': 0x20000,
    'PROCESS_ATTR_FIBER_STATE': 0x1000000
}

STOP_REASON = {
    'STOP_REASON_NOTHING': 0x0,
    'STOP_REASON_SUSPEND_PROCESS': 0x10001,
    'STOP_REASON_SUSPEND_THREAD': 0x10002,
    'STOP_REASON_APPLICATION_IS_SUSPENDED': 0x10003,
    'STOP_REASON_APPMGR_DETECTED_HUNGUP': 0x10004,
    'STOP_REASON_SPONTANEOUS_EXIT': 0x10005,
    'STOP_REASON_STACK_OVERFLOW': 0x10006,
    'STOP_REASON_SYSCALL_ERROR_ILLEGAL_CONTEXT': 0x10007,
    'STOP_REASON_SYSCALL_ERROR_CRITICAL_USAGE': 0x10008,
    'STOP_REASON_SYSCALL_ERROR_ILLEGAL_NUMBER': 0x10009,
    'STOP_REASON_HARDWARE_WATCHPOINT': 0x20001,
    'STOP_REASON_SOFTWARE_WATCHPOINT': 0x20002,
    'STOP_REASON_HARDWARE_BRKPT': 0x20003,
    'STOP_REASON_SOFTWARE_BRKPT': 0x20004,
    'STOP_REASON_STARTUP_FAILED': 0x20005,
    'STOP_REASON_PRX_STOP_INIT': 0x20006,
    'STOP_REASON_DTRACE_BRKPT': 0x20007,
    'STOP_REASON_EXCEPTION_UNDEF': 0x30002,
    'STOP_REASON_EXCEPTION_PREFETCH_ABORT': 0x30003,
    'STOP_REASON_EXCEPTION_DATA_ABORT': 0x30004,
    'STOP_REASON_FPU_VFP': 0x40001,
    'STOP_REASON_FPU_NEON': 0x40002,
    'STOP_REASON_GPU_EXCEPTION_': 0x50001,
    'STOP_REASON_INT_DIV0': 0x60080,
    'STOP_REASON_GPU_EXCEPTION': 0x70000,
    'STOP_REASON_UNRECOVERABLE_ERROR_LOW': 0x80000,
    'STOP_REASON_UNRECOVERABLE_ERROR_HIGH': 0x800ff
}

THREAD_STATUS = {
    'THREAD_STATUS_RUNNING': 0x1,
    'THREAD_STATUS_READY': 0x2,
    'THREAD_STATUS_STANDBY': 0x4,
    'THREAD_STATUS_WAITING': 0x8,
    'THREAD_STATUS_DORMANT': 0x10,
    'THREAD_STATUS_DELETED': 0x20,
    'THREAD_STATUS_DEAD': 0x40,
    'THREAD_STATUS_STAGNANT': 0x80,
    'THREAD_STATUS_VM_SUSPENDED': 0x100,
    'THREAD_STATUS_INSIDE_SYSCALL': 0x80000000
}

MODULE_TYPE = {
    'MODULE_TYPE_FIXED_ELF': 0x10,
    'MODULE_TYPE_PRX': 0x20
}

MODULE_FLAGS = {
    'MODULE_FLAGS_LOADED_COMMON_DIALOG_BUDGET': 0x1,
    'MODULE_FLAGS_LOADED_DEVTOOL_BUDGET': 0x2,
    'MODULE_FLAGS_SHARED_TEXT_MODULE': 0x100,
    'MODULE_FLAGS_SHAREABLE_TEXT_MODULE': 0x400,
    'MODULE_FLAGS_SYSTEM_MODULE': 0x1000,
    'MODULE_FLAGS_PROCESS_MAIN_MODULE': 0x4000,
    'MODULE_FLAGS_RELOCATABLE_MODULE': 0x8000
}

MODULE_STATUS = {
    'MODULE_STATUS_LOADED': 0x0,
    'MODULE_STATUS_STARTING': 0x1,
    'MODULE_STATUS_LIVE': 0x2,
    'MODULE_STATUS_STOPPING': 0x3,
    'MODULE_STATUS_STOPPED': 0x4
}

PRX_ATTR = {
    'PRX_ATTR_READABLE': 0x4,
    'PRX_ATTR_WRITABLE': 0x2,
    'PRX_ATTR_EXECUTABLE': 0x1
}

SYNC_PRIMITIVE_ATTR = {
        'SYNC_PRIMITIVE_ATTR_SHARED_OWNERSHIP': 0x80000
}

CoreFileInfo = Struct(
        "version" / Const(1, Int32ul),
        Int32ul,
        "field_08" / Int32ul,
        "field_0C" / Int32ul)

ProcessInfo = Struct(
        "version" / Const(1, Int32ul),
        Int32ul,
        "uid" / Hex(Int32ul),
        "attr" / VFlagsEnum(Int32ul, **PROCESS_ATTR),
        "name" / PaddedString(36, "utf8"),
        "cpu_affinity" / Int32ul,
        "entry" / Hex(Int32ul),
        "guid" / Hex(Int32ul),
        "ppid" / Hex(Int32ul),
        Int32ul,
        "stop_reason" / Enum(Int32ul, **STOP_REASON),
        Array(3, Int32ul),
        "path" / Aligned(4, PascalString(Int32ul, "utf8")),
        "start_exidx" / Hex(Int32ul),
        "end_exidx" / Hex(Int32ul),
        "start_extab" / Hex(Int32ul),
        "end_extab" / Hex(Int32ul),
        "process_time" / Optional(Int64ul))

ThreadInfoCommon = Struct(
        "uid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "init_attrs" / Hex(Int32ul),
        "current_attrs" / Hex(Int32ul),
        "status" / VFlagsEnum(Int32ul, **THREAD_STATUS),
        "entry_address" / Hex(Int32ul),
        "stack_addr_top" / Hex(Int32ul),
        "stack_size" / Hex(Int32ul),
        Int32ul,
        "arg_size" / Int32ul,
        "arg_blk_addr" / Hex(Int32ul),
        "init_prio" / Int32ul,
        "current_prio" / Int32ul,
        "init_cpu_aff_mask" / Hex(Int32ul),
        "current_cpu_aff_mask" / Hex(Int32ul),
        "last_cpuid" / Int32ul,
        "wait_state_type" / Int32ul,
        "wait_target_id" / Hex(Int32ul),
        "clock_run" / Int64ul,
        Int32ul,
        "stop_reason" / Enum(Int32ul, **STOP_REASON),
        Array(3, Int32ul),
        "exit_status" / Hex(Int32ul),
        "interrupt_preempt_count" / Int32ul,
        "thread_preempt_count" / Int32ul,
        "release_count" / Int32ul,
        "change_cpu_count" / Int32ul,
        "vfp_mode" / Int32ul,
        "pc" / Hex(Int32ul),
        "wait_timeout" / Int32ul)

ThreadInfo1 = Int32ul + ThreadInfoCommon + Struct(
        Int64ul,
        "wait_details" / Computed(lambda _: (0,)*9))
assert(ThreadInfo1.sizeof() == 0xAC)

ThreadInfo9 = Int32ul + ThreadInfoCommon + Struct(
        "wait_details" / Int32ul[8])
assert(ThreadInfo9.sizeof() == 0xC4)

ThreadInfo18 = Prefixed(Int32ul, includelength=True,
        subcon=ThreadInfoCommon + Struct(
        "wait_details" / Int32ul[9]))

ThreadsInfo = Struct(
        "version" / Int32ul,
        "items" / PrefixedArray(Int32ul, Switch(this._.version, {
             1: ThreadInfo1,
             9: ThreadInfo9,
            18: ThreadInfo18
        })))

ThreadRegInfoCommon = Struct(
        "tid" / Hex(Int32ul),
        "gpr" / Hex(Int32ul)[16],
        "cpsr" / Hex(Int32ul),
        "fpscr" / Hex(Int32ul),
        "tpidruro" / Hex(Int32ul),
        "neon" / Hex(BytesInteger(16, swapped=True))[16]
)
ThreadRegInfo1 = Struct(Int32ul) + ThreadRegInfoCommon
assert(ThreadRegInfo1.sizeof() == 0x154)
ThreadRegInfo17 = Struct("size" / Const(0x178, Int32ul)) + ThreadRegInfoCommon + Struct(
        "fpexc" / Hex(Int32ul),
        "tpidrurw" / Hex(Int32ul),
        "cpacr" / Hex(Int32ul),
        "dacr" / Hex(Int32ul),
        "dbgdscr" / Hex(Int32ul),
        "ifsr" / Hex(Int32ul),
        "ifar" / Hex(Int32ul),
        "dfsr" / Hex(Int32ul),
        "dfar" / Hex(Int32ul))
assert(ThreadRegInfo17.sizeof() == 0x178)

ThreadRegsInfo = Struct(
        "version" / Int32ul,
        "items" / PrefixedArray(Int32ul, Switch(this._.version, {
             1: ThreadRegInfo1,
            17: ThreadRegInfo17
        })))

SegmentInfo = Struct(
        "num" / Computed(this._index),
        Int32ul,
        "attr" / VFlagsEnum(Int32ul, **PRX_ATTR),
        "start" / Hex(Int32ul),
        "size" / Hex(Int32ul),
        "align" / Hex(Int32ul))

ModuleInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "sdk_version" / Hex(Int32ul),
        "module_version" / Hex(Int16ul),
        Int16ul,
        "type" / Enum(Int8ul, **MODULE_TYPE),
        Int8ul,
        "flags" / VFlagsEnum(Int16ul, **MODULE_FLAGS),
        "start_entry_addr" / Hex(Int32ul),
        "reference_count" / Int32ul,
        "stop_entry_addr" / Hex(Int32ul),
        "exit_entry_addr" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "status" / Enum(Int32ul, **MODULE_STATUS),
        "guid" / Hex(Int32ul),
        "segments" / PrefixedArray(Int32ul, SegmentInfo),
        "start_exidx" / Hex(Int32ul),
        "end_exidx" / Hex(Int32ul),
        "start_extab" / Hex(Int32ul),
        "end_extab" / Hex(Int32ul))

ModulesInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, ModuleInfo))

NIDAddr = Struct(
        "nid" / Hex(Int32ul),
        "addr" / Hex(Int32ul))

LibraryInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "module_id" / Hex(Int32ul),
        "attr" / Hex(Int32ul),
        "reference_count" / Int32ul,
        "exported_fn_count" / Hex(Rebuild(Int32ul, len_(this.exported_fn))),
        "exported_var_count" / Hex(Rebuild(Int32ul, len_(this.exported_var))),
        "tls_offs_count" / Hex(Rebuild(Int32ul, len_(this.tls_offs))),
        "client_modid_count" / Hex(Rebuild(Int32ul, len_(this.client_modid))),
        "exported_fn" / NIDAddr[this.exported_fn_count],
        "exported_var" / NIDAddr[this.exported_var_count],
        "tls_offs" / Int32ul[this.tls_offs_count],
        "client_modid" / Hex(Int32ul)[this.client_modid_count],
        "name" / Aligned(4, PascalString(Int32ul, "utf8")))

LibrariesInfo = Struct(
        "version" / Const(6, Int32ul),
        "items" / PrefixedArray(Int32ul, LibraryInfo))

MemoryBlockInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "type" / Hex(Int32ul),
        "header_addr" / Hex(Int32ul),
        "block_size" / Hex(Int32ul),
        Int32ul,
        Int32ul,
        "allocated_size" / Hex(Int32ul),
        "low_size" / Hex(Int32ul),
        "high_size" / Hex(Int32ul))

MemoryBlocksInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, MemoryBlockInfo))

FileInfo = Struct(
        Int32ul,
        "handle" / Hex(Int32ul),
        "attr" / Hex(Int32ul),
        "flags" / Hex(Int32ul),
        "open_process" / Hex(Int32ul),
        "mode" / Hex(Int32ul),
        "position" / Int64ul,
        "size" / Int64ul,
        "prio" / Int32ul,
        Int32ul[7],
        "real_path" / Aligned(4, PascalString(Int32ul, "utf8")),
        "open_path" / Aligned(4, PascalString(Int32ul, "utf8")))

FilesInfo = Struct(
        "version" / Const(5, Int32ul),
        "items" / PrefixedArray(Int32ul, FileInfo))

SemaphoreInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "creation_pid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "attr" / VFlagsEnum(Hex(Int32ul), **SYNC_PRIMITIVE_ATTR),
        "ref_count" / Int32ul,
        "init_value" / Int32ul,
        "current_value" / Int32ul,
        "max_value" / Int32ul,
        "wait_threads" / PrefixedArray(Int32ul, PidTid))

SemaphoresInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, SemaphoreInfo))

EventFlagInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "creation_pid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "attr" / VFlagsEnum(Hex(Int32ul), **SYNC_PRIMITIVE_ATTR),
        "ref_count" / Int32ul,
        "init_value" / Int32ul,
        "current_value" / Int32ul,
        "wait_threads" / PrefixedArray(Int32ul, PidTid))

EventFlagsInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, EventFlagInfo))

MutexInfoCommon = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "creation_pid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "attr" / VFlagsEnum(Hex(Int32ul), **SYNC_PRIMITIVE_ATTR),
        "ref_count" / Int32ul,
        "init_value" / Int32ul,
        "current_value" / Int32ul,
        "thread_owner_id" / Int32ul,
        "wait_threads" / PrefixedArray(Int32ul, PidTid))

MutexInfo1 = MutexInfoCommon + Struct(
        "ceiling_property" / Computed(lambda _: 0))

MutexInfo9 = MutexInfoCommon + Struct(
        "ceiling_property" / Int32ul)

MutexesInfo = Struct(
        "version" / Int32ul,
        "items" / PrefixedArray(Int32ul, Switch(this._.version, {
             1: MutexInfo1,
             9: MutexInfo9
        })))

LwMutexInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "attr" / VFlagsEnum(Hex(Int32ul), **SYNC_PRIMITIVE_ATTR),
        "work" / Hex(Int32ul),
        "init_value" / Int32ul,
        "current_value" / Int32ul,
        "thread_owner_id" / Hex(Int32ul),
        "wait_threads" / PrefixedArray(Int32ul, Tid))

LwMutexesInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, LwMutexInfo))

MesgPipeInfoCommon = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "creation_pid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "attr" / VFlagsEnum(Hex(Int32ul), **SYNC_PRIMITIVE_ATTR),
        "ref_count" / Int32ul,
        "buffer_byte_size" / Int32ul,
        "free_byte_size" / Int32ul,
        "send_threads_count" / Hex(Rebuild(Int32ul, len_(this.send_threads))),
        "recv_threads_count" / Hex(Rebuild(Int32ul, len_(this.recv_threads))),
        "send_threads" / PidTid[this.send_threads_count],
        "recv_threads" / PidTid[this.recv_threads_count]
)
MesgPipeInfo1  = MesgPipeInfoCommon + Struct(
        "event_pattern" / Computed(lambda _: 0),
        "user_data" / Computed(lambda _: 0))
MesgPipeInfo17 = MesgPipeInfoCommon + Struct(
        "event_pattern" / Hex(Int32ul),
        "user_data" / Hex(Int32ul)[2])

MesgPipesInfo = Struct(
        "version" / Int32ul,
        "items" / PrefixedArray(Int32ul, Switch(this._.version, {
              1: MesgPipeInfo1,
             17: MesgPipeInfo17
})))

MetaDataInfo = Struct(
        "key" / Hex(Int32ul),
        "value" / Aligned(4, PascalString(Int32ul, "utf8")))

MetaDatasInfo = Struct(
        "version" / Const(2, Int32ul),
        "items" / PrefixedArray(Int32ul, MetaDataInfo))

StackInfo = Struct(
        Int32ul,
        "tid" / Hex(Int32ul),
        "peak_use" / Hex(Int32ul),
        "current_use" / Hex(Int32ul))

StacksInfo = Struct(
        "version" / Const(4, Int32ul),
        "items" / PrefixedArray(Int32ul, StackInfo))

# Unknown structure
ApplicationInfo = Byte[128]
assert(ApplicationInfo.sizeof() == 0x80)

ApplicationsInfo = Struct(
        "version" / Const(6, Int32ul),
        "items" / ApplicationInfo[2])

ExtnlProcInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "budget_id" / Hex(Int32ul),
        "attr" / VFlagsEnum(Int32ul, **PROCESS_ATTR),
        "name" / PaddedString(32, "utf8"),
        "priority" / Hex(Int32ul),
        "cpu_affinity" / Int32ul,
        "entry" / Hex(Int32ul),
        "guid" / Hex(Int32ul),
        "ppid" / Hex(Int32ul),
        Hex(Int32ul),
        "stop_reason" / Enum(Int32ul, **STOP_REASON),
        Hex(Int32ul),
        Hex(Int32ul),
        Hex(Int32ul),
        "path" / Aligned(4, PascalString(Int32ul, "utf8")),
        "start_exidx" / Hex(Int32ul),
        "end_exidx" / Hex(Int32ul),
        "start_extab" / Hex(Int32ul),
        "end_extab" / Hex(Int32ul),
)

ExtnlProcsInfo = Struct(
        "version" / Const(6, Int32ul),
        "items" / PrefixedArray(Int32ul, ExtnlProcInfo))

TTYInfo = Struct(
        "version" / Const(8, Int32ul),
        Int32ul,
        "data" / PascalString(Int32ul, "utf8"))

TTYInfo2 = Struct(
        "version" / Const(19, Int32ul),
        Int32ul,
        "data" / PascalString(Int32ul, "utf8"))

class VitaAddress():
    def __init__(self, symbol, vaddr, module = None, segment = None, offset = None):
        self.__symbol = symbol
        self.__module = module
        self.__segment = segment
        self.__offset = offset
        self.__vaddr = vaddr

    def is_located(self):
        return self.__module and self.__segment and self.__offset

    def print_disas_if_available(self, elf):
        addr_to_display = self.__vaddr
        if addr_to_display & 1 == 0:
            state = "ARM"
        else:
            state = "Thumb"
            addr_to_display &= ~1

        if elf and self.is_located():
            iprint()
            iprint("DISASSEMBLY AROUND {}: 0x{:x} ({}):".format(self.__symbol, addr_to_display, state))
            elf.disas_around_addr(self.__offset)

    def to_string(self, elf=None):
        if self.is_located():
            output = "{}: 0x{:x} ({}@{} + 0x{:x}".format(self.__symbol, self.__vaddr,
                       self.__module.name, self.__segment.num, self.__offset)
            if elf and self.__module.name.endswith(".elf") and self.__segment.num == 1:
                output += " => {}".format(elf.addr2line(self.__offset))
            output += ')'
        else:
            output = "{}: 0x{:x}".format(self.__symbol, self.__vaddr)

        return output

    def __str__(self):
        return self.to_string()



class Segment():

    def __init__(self, vaddr, data):
        self.vaddr = vaddr
        self.data = data
        self.size = len(data)


class CoreParser():

    def _parse_generic(parser, field):
        def do_parse(self, note):
            obj = parser.parse(note)
            setattr(self, field, obj['items'])
        return do_parse

    def __init__(self, filename):
        try:
            f = gzip.open(filename, "rb")
            self.elf = ELFFile(f)
        except IOError:
            f.close()
            f = open(filename, "rb")
            self.elf = ELFFile(f)

        if (self.elf['e_type'] != 'ET_CORE' or
            self.elf['e_version'] != 'EV_CURRENT' or
            self.elf['e_machine'] != 'EM_ARM' or
            self.elf['e_flags'] != 0x5000000 or
            self.elf['e_entry'] != 0):
            raise Exception("Invalid PSP2 corefile")

        self.init_notes()

        for type_, note in self.notes.items():
            func = self.PARSERS.get(type_, None)
            if not func:
                continue
            func(self, note)

        self.map_threads()

        f.close()

    def init_notes(self):
        self.notes = dict()
        #self.notes_id = dict()
        self.segments = []

        for seg in self.elf.iter_segments():
            if seg.header.p_type == "PT_NOTE":
                for note in seg.iter_notes():
                    #self.notes_id[note["n_name"]] = note["n_type"]
                    self.notes[note["n_type"]] = note["n_desc"]
            elif seg.header.p_type == "PT_LOAD":
                self.segments.append(Segment(seg.header.p_vaddr, seg.data()))

        #print(self.notes.keys())
        #print(self.notes_id)
        #print(self.notes['SYSTEM_INFO'].hex())
        #print(SystemInfo.parse(self.notes['SYSTEM_INFO']))

    def parse_corefile(self, note):
        # Nothing to fetch, make sure everything is OK
        CoreFileInfo.parse(note)

    def parse_process(self, note):
        # Nothing to fetch, make sure everything is OK
        self.process = ProcessInfo.parse(note)

    def map_threads(self):
        self.tid_to_thread = dict()
        for thread in self.threads:
            self.tid_to_thread[thread.uid] = thread
        for regs in self.threadregs:
            self.tid_to_thread[regs.tid].regs = regs
        for stack in self.stacks:
            self.tid_to_thread[stack.tid].stack = stack

    def parse_tty(self, note):
        tty = TTYInfo.parse(note)
        # The string represents a block of memory with \0 when uninitialized
        self.tty = tty.data.rstrip('\0')

    def parse_tty2(self, note):
        tty2 = TTYInfo2.parse(note)
        # The string represents a block of memory with \0 when uninitialized
        self.tty2 = tty2.data.rstrip('\0')

    PARSERS = {
        4096: parse_corefile, # COREFILE_INFO
        # 4097: None, # SYSTEM_INFO
        4098: parse_process, # PROCESS_INFO
        4099: _parse_generic(ThreadsInfo, 'threads'), # THREAD_INFO
        4100: _parse_generic(ThreadRegsInfo, 'threadregs'), # THREAD_REG_INFO
        4101: _parse_generic(ModulesInfo, 'modules'), # MODULE_INFO
        4102: _parse_generic(LibrariesInfo, 'libraries'), # LIBRARY_INFO
        4103: _parse_generic(MemoryBlocksInfo, 'memblks'), # MEM_BLK_INFO
        4105: _parse_generic(FilesInfo, 'files'), # FILE_INFO
        4106: _parse_generic(SemaphoresInfo, 'semaphores'), # SEMAPHORE_INFO
        4107: _parse_generic(EventFlagsInfo, 'eventflags'), # EVENTFLAG_INFO
        4108: _parse_generic(MutexesInfo, 'mutexes'), # MUTEX_INFO
        4109: _parse_generic(LwMutexesInfo, 'lwmutexes'), # LWMUTEX_INFO
        4112: _parse_generic(MesgPipesInfo, 'mesgpipes'), # MESG_PIPE_INFO
        4121: _parse_generic(MetaDatasInfo, 'metadatas'), # META_DATA_INFO
        4123: _parse_generic(StacksInfo, 'stacks'), # STACK_INFO
        # 4124: None, # APP_INFO
        4126: _parse_generic(ExtnlProcsInfo, 'extnlprocs'), # EXTNL_PROC_INFO
        4138: parse_tty, # TTY_INFO
        # 4140: None, # EVENT_LOG_INFO
        # 4141: None, # SYSTEM_INFO2
        # 4142: None, # SUMMARY_INFO
        4145: parse_tty2, # TTY_INFO2
        # 8193: None, # GPU_ACT_INFO
    }

    def get_address_notation(self, symbol, vaddr):
        for module in self.modules:
            for segment in module.segments:
                if vaddr >= segment.start and vaddr < segment.start + segment.size:
                    return VitaAddress(symbol, vaddr, module, segment, vaddr - segment.start)
        return VitaAddress(symbol, vaddr)

    def read_vaddr(self, addr, size):
        for segment in self.segments:
            if addr >= segment.vaddr and addr < segment.vaddr + segment.size:
                addr -= segment.vaddr
                return segment.data[addr:addr+size]
        return None
