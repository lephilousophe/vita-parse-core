from elftools.elf.elffile import ELFFile

from collections import defaultdict
from argparse import ArgumentParser

from construct import Int32ul

from indent import indent, iprint
from elf import ElfParser
from core import CoreParser

str_stop_reason = defaultdict(str, {
    'STOP_REASON_NOTHING': "No reason",
    'STOP_REASON_EXCEPTION_UNDEF': "Undefined instruction exception",
    'STOP_REASON_EXCEPTION_PREFETCH_ABORT': "Prefetch abort exception",
    'STOP_REASON_EXCEPTION_DATA_ABORT': "Data abort exception",
    'STOP_REASON_INT_DIV0': "Division by zero",
})

str_thread_status = defaultdict(str, {
    'THREAD_STATUS_RUNNING': "Running",
    'THREAD_STATUS_WAITING': "Waiting",
    'THREAD_STATUS_DORMANT': "Dormant",
})

str_segment_attr = defaultdict(str, {
    'PRX_ATTR_READABLE': "Read",
    'PRX_ATTR_WRITABLE': "Write",
    'PRX_ATTR_EXECUTABLE': "Execute"
})

reg_names = {
    13: "SP",
    14: "LR",
    15: "PC",
}

def flags2str(attr, mapping=None):
    mask = filter(lambda k: not k.startswith('_') and attr[k], attr)
    if mapping:
        mask = map(lambda k: mapping.get(k, k), mask)
    return ' | '.join(mask)

core = None

isPC = True

def print_process_info(process):
    iprint(process.name)
    with indent():
        iprint("PID: {}".format(process.uid))
        iprint("Attributes: 0x{:x} ({})".format(process.attr._flagsvalue, flags2str(process.attr)))
        iprint("Affinity: {}".format(process.cpu_affinity))
        entry = core.get_address_notation("Entry", process.entry)
        iprint("Entry: {}".format(entry))
        iprint("GUID: {}".format(process.guid))
        iprint("Parent PID: 0x{:08x}".format(process.ppid))
        iprint("Stop reason: 0x{:x} ({})".format(int(process.stop_reason),
            str_stop_reason.get(process.stop_reason, process.stop_reason)))
        iprint("Path: {}".format(process.path.rstrip('\0')))

def print_extnlproc_info(extnlproc):
    iprint(extnlproc.name)
    with indent():
        iprint("PID: {}".format(extnlproc.uid))
        iprint("Attributes: 0x{:x} ({})".format(extnlproc.attr._flagsvalue, flags2str(extnlproc.attr)))
        iprint("Affinity: {}".format(extnlproc.cpu_affinity))
        # We don't have memory of map of external processes
        iprint("Entry: 0x{:08x}".format(extnlproc.entry))
        iprint("GUID: {}".format(extnlproc.guid))
        iprint("Parent PID: 0x{:08x}".format(extnlproc.ppid))
        iprint("Stop reason: 0x{:x} ({})".format(int(extnlproc.stop_reason),
            str_stop_reason.get(extnlproc.stop_reason, extnlproc.stop_reason)))
        iprint("Path: {}".format(extnlproc.path.rstrip('\0')))

def print_module_info(module):
    iprint(module.name)
    with indent():
        iprint("Type: {}".format(module.type))
        iprint("Flags: 0x{:x} ({})".format(module.flags._flagsvalue,
            flags2str(module.flags)))
        iprint("Status: {}".format(module.status))
        for x, segment in enumerate(module.segments):
            iprint("Segment {}".format(x + 1))
            with indent():
                iprint("Start: 0x{:x}".format(segment.start))
                iprint("Size: 0x{:x} bytes".format(segment.size))
                iprint("Attributes: 0x{:x} ({})".format(segment.attr._flagsvalue,
                    flags2str(segment.attr, str_segment_attr)))
                iprint("Alignment: 0x{:x}".format(segment.align))

def print_thread_info(thread, elf=None):
    iprint(thread.name)
    with indent():
        iprint("ID: 0x{:x}".format(thread.uid))
        iprint("Status: 0x{:x} ({})".format(thread.status._flagsvalue,
            flags2str(thread.status, str_thread_status)))
        iprint("Stop reason: 0x{:x} ({})".format(int(thread.stop_reason),
            str_stop_reason.get(thread.stop_reason, thread.stop_reason)))
        entry = core.get_address_notation("Entry", thread.entry_address)
        iprint("Entry: {}".format(entry))
        pc = core.get_address_notation("PC", thread.pc)
        iprint(pc.to_string(elf))
        if not pc.is_located():
            iprint(core.get_address_notation("LR", thread.regs.gpr[14]).to_string(elf))
        iprint("Current stack usage: {}/{} ({}%)".format(thread.stack.current_use, thread.stack_size,
            int(thread.stack.current_use / thread.stack_size * 100)))
        iprint("Peak stack usage: {}/{} ({}%)".format(thread.stack.peak_use, thread.stack_size,
            int(thread.stack.peak_use / thread.stack_size * 100)))

def print_memory_block_info(memblk):
    iprint(memblk.name)
    with indent():
        iprint("ID: 0x{:x}".format(memblk.uid))
        iprint("Type: 0x{:x}".format(memblk.type))
        iprint("Header address: 0x{:08x}".format(memblk.header_addr))
        iprint("Block size: 0x{:x}".format(memblk.block_size, memblk.block_size))
        iprint("Sizes: allocated=0x{:x} min=0x{:x} high=0x{:x}".format(memblk.allocated_size, memblk.low_size, memblk.high_size))

def print_file_info(file):
    iprint("ID: 0x{:x}".format(file.handle))
    with indent():
        iprint("Opener PID: 0x{:x}".format(file.open_process))
        open_path = file.open_path.rstrip('\0') or '<Unknown>'
        real_path = file.real_path.rstrip('\0') or '<Unknown>'
        iprint("Paths: {} => {}".format(open_path, real_path))
        iprint("Attributes: 0x{:x}".format(file.attr))
        iprint("Flags: 0x{:x}".format(file.flags))
        iprint("Mode: 0x{:x}".format(file.mode))
        iprint("Position: 0x{:x}/0x{:x}".format(file.position, file.size))

def print_semaphore_info(semaphore):
    iprint(semaphore.name)
    with indent():
        iprint("ID: 0x{:x}".format(semaphore.uid))
        iprint("Creator PID: 0x{:x}".format(semaphore.creation_pid))
        iprint("Attr: 0x{:x} ({})".format(semaphore.attr._flagsvalue, flags2str(semaphore.attr)))
        iprint("Reference count: {}".format(semaphore.ref_count))
        iprint("Values: init={} current={} max={}".format(semaphore.init_value, semaphore.current_value, semaphore.max_value))
        if len(semaphore.wait_threads) > 0:
            iprint("PID/TID waiting:")
            with indent():
                for thread in semaphore.wait_threads:
                    iprint("0x{:x}/0x{:x}".format(thread.pid, thread.tid))

def print_eventflag_info(eventflag):
    iprint(eventflag.name)
    with indent():
        iprint("ID: 0x{:x}".format(eventflag.uid))
        iprint("Creator PID: 0x{:x}".format(eventflag.creation_pid))
        iprint("Attr: 0x{:x} ({})".format(eventflag.attr._flagsvalue, flags2str(eventflag.attr)))
        iprint("Reference count: {}".format(eventflag.ref_count))
        iprint("Values: init={} current={}".format(eventflag.init_value, eventflag.current_value))
        if len(eventflag.wait_threads) > 0:
            iprint("PID/TID waiting:")
            with indent():
                for thread in eventflag.wait_threads:
                    iprint("0x{:x}/0x{:x}".format(thread.pid, thread.tid))

def print_mutex_info(mutex):
    iprint(mutex.name)
    with indent():
        iprint("ID: 0x{:x}".format(mutex.uid))
        iprint("Creator PID: 0x{:x}".format(mutex.creation_pid))
        iprint("Attr: 0x{:x} ({})".format(mutex.attr._flagsvalue, flags2str(mutex.attr)))
        iprint("Reference count: {}".format(mutex.ref_count))
        iprint("Values: init={} current={}".format(mutex.init_value, mutex.current_value))
        iprint("Current owner ID: 0x{:08x}".format(mutex.thread_owner_id))
        iprint("Ceiling property: 0x{:08x}".format(mutex.ceiling_property))
        if len(mutex.wait_threads):
            iprint("PID/TID waiting:")
            with indent():
                for thread in mutex.wait_threads:
                    iprint("0x{:x}/0x{:x}".format(thread.pid, thread.tid))

def print_lwmutex_info(lwmutex):
    iprint(lwmutex.name)
    with indent():
        iprint("ID: 0x{:x}".format(lwmutex.uid))
        iprint("Attr: 0x{:x} ({})".format(lwmutex.attr._flagsvalue, flags2str(lwmutex.attr)))
        iprint("Work pointer: 0x{:08x}".format(lwmutex.work))
        iprint("Counts: init={} current={}".format(lwmutex.init_value, lwmutex.current_value))
        iprint("Current owner ID: 0x{:08x}".format(lwmutex.thread_owner_id))
        if len(lwmutex.wait_threads):
            iprint("TID waiting:")
            with indent():
                for tid in lwmutex.wait_threads:
                    iprint("0x{:x}".format(tid))

def print_mesg_pipe_info(mesg_pipe):
    iprint(mesg_pipe.name)
    with indent():
        iprint("ID: 0x{:x}".format(mesg_pipe.uid))
        iprint("Creator PID: 0x{:x}".format(mesg_pipe.creation_pid))
        iprint("Attr: 0x{:x} ({})".format(mesg_pipe.attr._flagsvalue, flags2str(mesg_pipe.attr)))
        iprint("Reference count: {}".format(mesg_pipe.ref_count))
        iprint("Buffer free: {}/{}".format(mesg_pipe.free_byte_size, mesg_pipe.buffer_byte_size))
        if len(mesg_pipe.send_threads):
            iprint("Sending PID/TID:")
            with indent():
                for thread in mesg_pipe.send_threads:
                    iprint("0x{:x}/0x{:x}".format(thread.pid, thread.tid))
        if len(mesg_pipe.recv_threads):
            iprint("Recving PID/TID:")
            with indent():
                for thread in mesg_pipe.recv_threads:
                    iprint("0x{:x}/0x{:x}".format(thread.pid, thread.tid))

def main():
    global core

    parser = ArgumentParser()
    parser.add_argument("-s", "--stack-size-to-print", dest="stacksize",
                        type=int, help="Number of addresses of the stack to print", metavar="SIZE", default=24)
    parser.add_argument("corefile")
    parser.add_argument("elffile", nargs='?', default=None)
    args = parser.parse_args()
    stackSize = args.stacksize

    if args.elffile:
        elf = ElfParser(args.elffile)
    else:
        elf = None
    core = CoreParser(args.corefile)
    iprint("=== PROCESSES ===")
    print_process_info(core.process)
    iprint()
    for extnlproc in core.extnlprocs:
        if extnlproc.uid == core.process.uid:
            continue
        print_extnlproc_info(extnlproc)
    iprint()

    iprint("=== MODULES ===")
    with indent():
        for module in core.modules:
            print_module_info(module)
    iprint()

    iprint("=== THREADS ===")
    crashed = []
    with indent():
        for thread in core.threads:
            if thread.stop_reason != 'STOP_REASON_NOTHING':
                crashed.append(thread)
            print_thread_info(thread, elf)
    iprint()
    for thread in crashed:
        iprint('=== THREAD "{}" <0x{:x}> CRASHED ({}) ==='.format(thread.name, thread.uid,
            str_stop_reason.get(thread.stop_reason, thread.stop_reason)))

        pc = core.get_address_notation('PC', thread.pc)
        pc.print_disas_if_available(elf)
        lr = core.get_address_notation('LR', thread.regs.gpr[14])
        lr.print_disas_if_available(elf)

        iprint("REGISTERS:")
        with indent():
            for x in range(14):
                reg = reg_names.get(x, "R{}".format(x))
                iprint("{:3}: 0x{:08x}".format(reg, thread.regs.gpr[x]))

            iprint(pc)
            iprint(lr)
            iprint("CPSR: 0x{:x}".format(thread.regs.cpsr))

            for x in range(16):
                reg = "Q{}".format(x)
                iprint("{:3}: 0x{:032x}".format(reg, thread.regs.neon[x]))


        iprint()

        iprint("STACK CONTENTS AROUND SP:")
        with indent():
            sp = thread.regs.gpr[13]
            for x in range(-16, stackSize):
                addr = 4 * x + sp
                data = core.read_vaddr(addr, 4)
                if data:
                    data = Int32ul.parse(data)
                    prefix = "     "
                    if addr == sp:
                        prefix = "SP =>"
                    data_notation = core.get_address_notation("{} 0x{:x}".format(prefix, addr), data)
                    iprint(data_notation.to_string(elf))
    iprint()

    iprint("=== MEMORY BLOCKS ===")
    with indent():
        for memblk in core.memblks:
            print_memory_block_info(memblk)
    iprint()

    iprint("=== FILES ===")
    with indent():
        for file in core.files:
            print_file_info(file)
    iprint()

    iprint("=== SEMAPHORES ===")
    with indent():
        for semaphore in core.semaphores:
            print_semaphore_info(semaphore)
    iprint()

    iprint("=== EVENT FLAGS ===")
    with indent():
        for eventflag in core.eventflags:
            print_eventflag_info(eventflag)
    iprint()

    iprint("=== MUTEXES ===")
    with indent():
        for mutex in core.mutexes:
            print_mutex_info(mutex)
    iprint()

    iprint("=== LW MUTEXES ===")
    with indent():
        for lwmutex in core.lwmutexes:
            print_lwmutex_info(lwmutex)
    iprint()

    iprint("=== TTY ===")
    with indent():
        for l in core.tty.split('\n'):
            iprint(l)
    iprint()

    iprint("=== TTY2 ===")
    with indent():
        for l in core.tty2.split('\n'):
            iprint(l)
    iprint()

if __name__ == "__main__":
    main()
