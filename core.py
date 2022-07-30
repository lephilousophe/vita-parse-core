import gzip

from elftools.elf.elffile import ELFFile

from sys import argv
from collections import defaultdict

from indent import indent, iprint

from construct import *

ThreadInfoCommon = Struct(
        "uid" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "init_attrs" / Hex(Int32ul),
        "current_attrs" / Hex(Int32ul),
        "status" / Hex(Int32ul),
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
        "stop_reason" / Hex(Int32ul),
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
        "ukn" / Int64ul,
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
        "attr" / Hex(Int32ul),
        "start" / Hex(Int32ul),
        "size" / Hex(Int32ul),
        "align" / Hex(Int32ul))

ModuleInfo = Struct(
        Int32ul,
        "uid" / Hex(Int32ul),
        "sdk_version" / Hex(Int32ul),
        "module_version" / Hex(Int16ul),
        Int16ul,
        "type" / Int8ul,
        Int8ul,
        "flags" / Hex(Int16ul),
        "start_entry_addr" / Hex(Int32ul),
        "reference_count" / Int32ul,
        "stop_entry_addr" / Hex(Int32ul),
        "exit_entry_addr" / Hex(Int32ul),
        "name" / PaddedString(32, "utf8"),
        "status" / Hex(Int32ul),
        "ukn" / Hex(Int32ul),
        "segments" / PrefixedArray(Int32ul, SegmentInfo),
        "start_exidx" / Hex(Int32ul),
        "end_exidx" / Hex(Int32ul),
        "start_extab" / Hex(Int32ul),
        "end_extab" / Hex(Int32ul))

ModulesInfo = Struct(
        "version" / Const(1, Int32ul),
        "items" / PrefixedArray(Int32ul, ModuleInfo))


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

    def __init__(self, filename):
        try:
            f = gzip.open(filename, "rb")
            self.elf = ELFFile(f)
        except IOError:
            f.close()
            f = open(filename, "rb")
            self.elf = ELFFile(f)

        self.init_notes()

        self.parse_modules()
        self.parse_threads()
        self.parse_thread_regs()

        f.close()

    def init_notes(self):
        self.notes = dict()
        self.segments = []

        for seg in self.elf.iter_segments():
            if seg.header.p_type == "PT_NOTE":
                for note in seg.iter_notes():
                    self.notes[note["n_name"]] = note["n_desc"]
            elif seg.header.p_type == "PT_LOAD":
                self.segments.append(Segment(seg.header.p_vaddr, seg.data()))


    def parse_modules(self):
        data = self.notes["MODULE_INFO"]

        modules = ModulesInfo.parse(data)
        self.modules = modules['items']

    def parse_threads(self):
        data = self.notes["THREAD_INFO"]
        threads = ThreadsInfo.parse(data)

        self.tid_to_thread = dict()
        self.threads = threads['items']
        for thread in self.threads:
            self.tid_to_thread[thread.uid] = thread

    def parse_thread_regs(self):
        data = self.notes["THREAD_REG_INFO"]
        thdregs = ThreadRegsInfo.parse(data)

        for regs in thdregs['items']:
            self.tid_to_thread[regs.tid].regs = regs

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
