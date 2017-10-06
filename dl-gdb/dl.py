# Import additional modules
from gdb import (Breakpoint, Function, Command, Parameter, write, execute,
                 parse_and_eval, selected_inferior, selected_thread, error,
                 decode_line, STDERR, COMMAND_OBSCURE, PARAM_ENUM,
                 PARAM_BOOLEAN, COMPLETE_LOCATION, COMPLETE_NONE)
from os import access, listdir, path, W_OK
from re import search
import parser

HEX_RE = "[0-9a-fA-F]"
REGS = [
    "pc", "ss", "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi", "r8",
    "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"]

# Checkpoints datastructures
cpbreaks = {}
cpb_counter = 0
cps = {}
cp_counter = 0
# rollback related flags and variables
saved_regs = None


###############################################################################
# Printing/Logging utilities
###############################################################################
def print_debug(msg, exec_cb=None):
    if dl_debug.value:
        write("DEBUG: {}.\n".format(msg))
        if exec_cb:
            exec_cb()


def print_info(msg):
    write("INFO: {}.\n".format(msg))


def print_error(msg, prepend_nl=False):
    write(
        "{}ERROR: {}.\n".format("\n" if prepend_nl else "", msg), stream=STDERR)


###############################################################################
# Utilities
###############################################################################
class MapEntry:
    def __init__(self, line):
        m = search(
            "\s*({}+)-({}+)\s+(.{{4}})\s+{}+\s+{}+:{}+\s+\d+(.*)".format(
                HEX_RE, HEX_RE, HEX_RE, HEX_RE, HEX_RE), line)
        if not m:
            print_error("unable to parse map entry")
            print_error("string: '{}'".format(line.strip()))
            raise Exception()

        self.start_addr = int(m.group(1), 16)
        self.end_addr = int(m.group(2), 16)
        permissions = m.group(3)
        self.is_read = permissions[0] == "r"
        self.is_write = permissions[1] == "w"
        self.is_exec = permissions[2] == "x"
        self.is_private = permissions[3] == "p"
        self.pathname = m.group(4).strip()

    def __repr__(self):
        return str((
            hex(self.start_addr), hex(self.end_addr),
            self.is_read, self.is_write, self.is_exec, self.is_private,
            self.pathname))


class KDLUtil:
    # XXX: rename when the module is renamed to KDL
    CONF_DIR = "/proc/sys/smmap/conf"
    STATS_DIR = "/proc/sys/smmap/stats"
    worker_thread_id = None

    @staticmethod
    def is_proc_running():
        return selected_inferior().pid > 0

    @staticmethod
    def is_kdl_initialized():
        return KDLUtil.exec_cmd("dl_is_initialized()", False)

    @staticmethod
    def get_ondemand_vars(expr):
        if dl_ondemand_rb.value:
            # converts conditional expressions from C to python
            expr = expr
            expr = expr.replace("||", "or")
            expr = expr.replace("&&", "and")
            expr = expr.replace("!", "not ")
            st = parser.expr(expr)
            code = parser.compilest(st)
            return code.co_names

        return None

    @staticmethod
    def exec_cmd(cmd, is_kdl_op=True):
        '''simple wrapper to execute KDL commands'''
        if not KDLUtil.is_proc_running():
            return None

        if is_kdl_op and not KDLUtil.is_kdl_initialized():
            print_error("kdl was not initialized.")
            return None

        print_debug("executing command: {}".format(cmd))
        ret = parse_and_eval(cmd)
        print_debug("{} returned {}".format(cmd, ret))
        return ret

    @staticmethod
    def switch_thread(tid):
        if not KDLUtil.is_proc_running():
            return None

        '''switch execution selection the thread with the requested tid'''
        cmd = "thread {}".format(tid)
        print_debug("executing command: {}".format(cmd))
        ret = execute(cmd, to_string=True)
        print_debug("\n{} returned {}".format(cmd, ret))

    @staticmethod
    def get_worker_tid():
        if not KDLUtil.worker_thread_id:
            worker_mem = int(parse_and_eval("(unsigned long) kdlctl_wmem"))
            ret = KDLUtil.exec_cmd(
                "dl_get_worker_tid(0x{:x})".format(worker_mem), False)
            if ret is None or int(ret) == 0:
                return

            worker_lwp = int(ret)
            worker_thread = [t for t in selected_inferior().threads()
                             if t.ptid[1] == worker_lwp][0]
            KDLUtil.worker_thread_id = worker_thread.num

        return int(KDLUtil.worker_thread_id)

    @staticmethod
    def reset_worker_tid():
        KDLUtil.worker_thread_id = None

    @staticmethod
    def switched_exec_cmd(cmd):
        '''
        function used to execute kdl operations which change the pages
        of the debugged process. This is the case for rollback and restore
        operations.

        NB: this command execution is slower since it uses scheduler locking
        '''
        # force all threads to stop when executing kdlctl in the worker thread
        execute("set scheduler-locking on")
        execute("set unwindonsignal on")
        # switch to worker thread
        tid = KDLUtil.get_worker_tid()
        if tid is None or int(tid) == 0:
            print_error("unable to complete switched command execution")
            return None

        current_tid = selected_thread().num
        KDLUtil.switch_thread(tid)
        # execute the command
        ret = KDLUtil.exec_cmd(cmd, True)
        # switch thread back to the previously executing one
        KDLUtil.switch_thread(current_tid)
        # Allow thread to run again (we unblock our worker thread)
        execute("set unwindonsignal off")
        execute("set scheduler-locking off")

        return ret

    @staticmethod
    def rollback_regs(cp, info):
        global saved_regs

        if not dl_track_regs.value:
            return

        # save the current register value
        if not saved_regs:
            saved_regs = {}
            for reg in REGS:
                saved_regs[reg] = int(parse_and_eval(
                    "(unsigned long) ${}".format(reg) if reg != "eflags"
                    else "(unsigned int) ${}".format(reg)))

        # rollback to the old register value
        for reg, value in list(info["regs"].items()):
            if reg == "eflags":
                KDLUtil.exec_cmd("$eflags = (unsigned int) $eflags", False)
            else:
                KDLUtil.exec_cmd("${} = {}".format(reg, value), False)

    @staticmethod
    def restore_regs():
        global saved_regs

        if not dl_track_regs.value:
            return

        if saved_regs:
            for reg, value in list(saved_regs.items()):
                if reg == "eflags":
                    KDLUtil.exec_cmd("$eflags = (unsigned int) $eflags", False)
                else:
                    KDLUtil.exec_cmd("${} = {}".format(reg, value), False)
            saved_regs = None

    @staticmethod
    def search_start(cps):
        if len(cps) <= 1:
            return

        ret = KDLUtil.exec_cmd("dl_search_start()")
        if ret is None or int(ret) < 0:
            print_error("unable to initialized search")

    @staticmethod
    def search_stop(cps):
        if len(cps) <= 1:
            return

        ret = KDLUtil.exec_cmd("dl_search_stop()")
        if ret is None or int(ret) < 0:
            print_error("unable to clean up search")

    @staticmethod
    def is_in_rollback():
        ret = KDLUtil.exec_cmd("dl_is_in_rb()")
        if ret is None or int(ret) < 0:
            print_error(
                "unable to determine the state of the process "
                "(err={})".format(ret))

        return True if ret == 1 else False

    @staticmethod
    def rollback(cp, variables=None):
        info = KDLUtil.get_info(cp)
        if not info:
            return (False, None)

        # rollback request is performed on all the pages
        if not info["from_kdl"]:
            KDLUtil.rollback_regs(cp, info)

        if not variables:
            ret = KDLUtil.switched_exec_cmd("dl_rollback({})".format(cp))
            if ret is None or ret != 0:
                print_error("unable to rollback state")
                return (False, None)
        else:
            # rollback is performed only on the affected variables
            varsaddr = KDLUtil.exec_cmd(
                "dl_vars_alloc({})".format(len(variables)))
            if varsaddr is None or int(varsaddr) == 0:
                print_error("unable to execute on-demand rollback")
                return (False, None)

            try:
                for variable, index in zip(variables,
                                           list(range(len(variables)))):

                    varaddr = parse_and_eval("&{}".format(variable))
                    varsize = parse_and_eval("sizeof({})".format(variable))
                    index = KDLUtil.exec_cmd(
                        "dl_vars_set({}, {}, {}, {})".format(
                            varsaddr, varaddr, varsize, index))
                    if index is None:
                        print_error("unable to prepare on-demand rollback")
                        return (False, None)

            except Exception as e:
                print_error("unable to set rollback-vars {} (error: {})".format(
                    variable, str(e)))
                # ignoring return value since the called function does not
                # return a value to the caller.
                return (False, None)

            ret = KDLUtil.switched_exec_cmd(
                "dl_rollback_ondemand({}, {})".format(varsaddr, cp))
            if ret is None or int(ret) != 0:
                print_error(
                    "unable to execute rollback-ondemand (err: {})".format(ret))
                return False

        return (True, info["from_kdl"])

    @staticmethod
    def restore():
        ret = KDLUtil.switched_exec_cmd("dl_restore()")
        if ret is None or int(ret) != 0:
            print_error("unable to restore state")
            return False

        KDLUtil.restore_regs()
        return True

    @staticmethod
    def kdl_init(location=None, bsize=None):
        success = True
        if not KDLUtil.is_kdl_initialized():
            # initialized worker thread for tmtl operations
            ret = KDLUtil.exec_cmd("dl_init()", False)
            if ret is None or int(ret) < 0:
                print_error("Unable to initialized kdl worker")
                return False

            # set maps for each memory area marked as writable
            if not location or not bsize:
                print_debug("initializing kdl on the whole process memory")
                areas = KDLUtil.find_maps()
                for area in areas:
                    ret = KDLUtil.exec_cmd(
                        "dl_map(0x{:x}, (void *) 0, {})".format(
                            area['start'], area['size']), False)
                    if ret is None or int(ret) != 0:
                        print_error(
                            "unable to map @addr={}, size={} (err: {})".format(
                                area['start'], area['size'], ret))
                        success = False
            else:
                print_debug(
                    "initializing kdl on specified area. "
                    "location: {}, size (bytes): {}".format(location, bsize))
                locaddr = int(parse_and_eval(
                    "(unsigned long) {}".format(location)))
                ret = KDLUtil.exec_cmd(
                    "dl_map(0x{:x}, (void *) 0, {})".format(locaddr, bsize),
                    False)
                if ret is None or int(ret) != 0:
                    print_error(
                        "unable to map @addr={}, size={} (err: {})".format(
                            locaddr, bsize, ret))
                    success = False

            # clear statistics
            KDLUtil.clear_all_stats()

        return success

    @staticmethod
    def load_mappings():
        def is_in(addr, mapping):
            return addr >= mapping.start_addr and addr < mapping.end_addr

        inferior = selected_inferior()
        if not inferior or not inferior.pid:
            return []

        mappings = []
        with open("/proc/{}/maps".format(inferior.pid), "r") as f:
            lines = f.readlines()
            # determine the worker utils and stack addresses
            worker_mem = int(parse_and_eval("(unsigned long) kdlctl_wmem"))
            wutils = parse_and_eval("(kdlctl_wmem_t *) kdlctl_wmem")
            worker_stack = wutils["stack"]
            # determine the text address
            main_addr = int(
                str(parse_and_eval("&main")).split(" ")[0], 16)
            # determine the data address
            data_addr = int(
                str(parse_and_eval("&__data_start")).split(" ")[0], 16)

            for line in lines:
                entry = MapEntry(line)
                if is_in(worker_mem, entry) or is_in(worker_stack, entry):
                    entry.pathname = "[worker]"
                elif is_in(main_addr, entry):
                    entry.pathname = "[text]"
                elif is_in(data_addr, entry):
                    entry.pathname = "[data]"
                elif entry.pathname.find("libkdl.so") > -1:
                    entry.pathname = "[kdl]"
                elif not entry.pathname and mappings[-1].pathname == "[kdl]":
                    entry.pathname = "[kdl]"
                mappings.append(entry)

        return mappings

    @staticmethod
    def get_base_addr():
        archstr = execute("show architecture", to_string=True)
        match = search("\(currently\s+(.*)\)", archstr)
        if not match:
            print_error("unable to read architecture")
            raise Exception()

        arch = match.group(1)

        addr_start = 0
        if arch == "i386":
            addr_end = (1024**3 * 3)
        elif arch == "i386:x86-64":
            addr_end = 2**47
        else:
            print_error("unsupported architecture")
            raise Exception()

        return (addr_start, addr_end)

    @staticmethod
    def find_maps(labels=None):
        '''
        Find the memory address for all the areas that are put under kdl. If
        labels are specified, find-maps will parse the process mappings and
        locate only the specified memory areas.
        '''

        # load the maps of the process
        mappings = KDLUtil.load_mappings()

        areas = []
        if labels:
            # when specified by the user, just select the areas determined by
            # the specified labels
            for entry in mappings:
                if entry.pathname in labels:
                    area = {
                        "start": entry.start_addr,
                        "end": entry.end_addr,
                        "size": entry.end_addr-entry.start_addr
                    }
                    areas.append(area)

        else:
            # if no labels are specified, try to set under kdl the whole
            # address space of the process.

            # determine the architecture of the target
            addr_start, addr_end = KDLUtil.get_base_addr()

            # determine the set of areas that need to be blacklisted so that
            # are not put under checkpoint.
            blacklist = []
            for entry in mappings:
                is_worker = entry.pathname == "[worker]"
                is_kdl = entry.pathname == "[kdl]"

                if is_worker or is_kdl:
                    blacklist.append(entry)

            # extract the addresses of the areas that will be checkpoitned
            areas.append({
                "start": addr_start, "end": addr_end,
                "size": addr_end-addr_start})
            for entry in blacklist:
                area = areas.pop()
                if entry.start_addr - area["start"] > 0:
                    # if non-zero, add the first half to the list
                    areas.append({
                        "start": area["start"], "end": entry.start_addr,
                        "size": entry.start_addr - area["start"]})

                if area["end"] - entry.end_addr > 0:
                    # if non-zero, add the second half to the list
                    areas.append({
                        "start": entry.end_addr, "end": area["end"],
                        "size": area["end"] - entry.end_addr})

        return areas

    @staticmethod
    def list_proc_files(directory, has_all=True, is_write=False):
        '''list all statistics available in kdl via the proc filesystem.'''

        files = listdir(directory) if path.exists(directory) else []
        entries = [f for f in files
                   if not is_write or access("{}/{}".format(
                       directory, f), W_OK)]
        if has_all and len(entries) > 0:
            entries.append("all")
        return entries

    @staticmethod
    def read_proc_files(directory, filenames):
        result = []
        for filename in filenames:
            if filename == "all":
                continue

            procfile = "{}/{}".format(directory, filename)
            content = ""
            try:
                with open(procfile, "r") as f:
                    content = f.read().replace("\n", "")
            except IOError as e:
                print_error("IO error on proc file '{}' ({})".format(
                    filename, str(e)))
                continue

            result.append((filename, content))

        return result

    @staticmethod
    def write_proc_files(directory, filenames, value):
        if not value.isdigit():
            print_error("specified something different from an integer")
            return

        for filename in filenames:
            if filename == "all":
                continue

            procfile = "{}/{}".format(directory, filename)
            try:
                with open(procfile, "w+") as f:
                    f.write(value)
                    f.flush()
            except IOError:
                print_error("wrong option specified '{}'".format(filename))
                continue

    @staticmethod
    def clear_all_stats():
        stats = KDLUtil.list_proc_files(KDLUtil.STATS_DIR, is_write=True)
        KDLUtil.write_proc_files(KDLUtil.STATS_DIR, stats, "0")

    @staticmethod
    def show_all_stats():
        stats = KDLUtil.list_proc_files(KDLUtil.STATS_DIR)
        values = KDLUtil.read_proc_files(KDLUtil.STATS_DIR, stats)
        for value in values:
            write("  {}: {}\n".format(value[0], value[1]))

    @staticmethod
    def take_cp():
        if not KDLUtil.is_kdl_initialized():
            print_error("unable to take checkpoint, kdl was not initialized")
            return False

        # retrieve the registers information
        if dl_track_regs.value:
            KDLUtil.exec_cmd("$info = dl_cp_info_alloc()")
            for reg in REGS:
                if reg == "eflags":
                    KDLUtil.exec_cmd(
                        "$info.eflags = (unsigned int) $eflags", False)
                else:
                    KDLUtil.exec_cmd(
                        "$info.{0} = ${0}".format(reg), False)

        else:
            KDLUtil.exec_cmd("$info = (void *) 0")

        # Take a checkpoint.
        ret = KDLUtil.exec_cmd("dl_checkpoint($info)")
        if ret is None or int(ret) != 0:
            print_error(
                "error occured while checkpointing (err: {})".format(ret))
            return False

        print_debug("print stats", KDLUtil.show_all_stats)
        return True

    @staticmethod
    def delete_breakpoint(bp):
        # In case hardware breakpoints were enabled, we need to delete also
        # the hardware breakpoint associated to the software breakpoint just
        # deleted
        if bp.is_hw:
            addr = decode_line(bp.location)[1][0].pc
            ret = KDLUtil.exec_cmd(
                "dl_drop_checkpoint(0x{:x})".format(addr))
            if not ret or ret != 0:
                print_error("unable to remove hardware breakpoint")
                return False
        bp.delete()
        return True

    @staticmethod
    def list2specifier(cpl):
        def finalize_interval(interval, result):
            result.append((interval[0], interval[-1]))
            del interval[:]

        if len(cpl) == 1:
            return list(cpl)

        # make the list unique and sorted
        newl = list(set(cpl))
        newl.sort()

        result = []
        interval = []
        for prev, next in zip(newl, newl[1:]):
            if prev + 1 == next:
                interval.append(prev)
            elif interval:
                # prev is the last element of the current inteval hence
                # can be appended to the current interval before finalizing
                interval.append(prev)
                finalize_interval(interval, result)
            else:
                result.append(prev)

            # special case: last element needs to be treated separately
            if next == newl[-1]:
                (interval if prev + 1 == next else result).append(next)

        if interval:
            finalize_interval(interval, result)

        return result

    @staticmethod
    def get_info(cp_id=-1):
        info = KDLUtil.exec_cmd("dl_get_info({})".format(cp_id))
        if not info:
            print_error("unable to retrieve info (err: {})".format(info))
            return None

        rinfo = {}
        rinfo["cp_id"] = int(info["cp_id"])
        rinfo["max_cp_id"] = int(info["max_cp_id"])
        rinfo["is_in_rollback"] = bool(info["is_in_rollback"])
        # Registers
        rinfo["regs"] = {}
        for reg in REGS:
            rinfo["regs"][reg] = int(info["cp_info"][reg])
        # Other flags
        rinfo["from_kdl"] = bool(info["cp_info"]["from_kdl"])
        rinfo["is_unknown"] = bool(info["cp_info"]["is_unknown"])

        return rinfo


# Force the kdl shared library to be loaded in the address-space of the
# program debugged
# XXX: fix this to work with the proper path.
#execute(
#    "set exec-wrapper env LD_PRELOAD="
#    "${DELOREAN_REPO_PATH}/kdl/libkdl.so")


###############################################################################
# Parameters
###############################################################################
class DLDebug(Parameter):
    '''enable/disable debugging information for the DL commands'''
    def __init__(self):
        super(DLDebug, self).__init__(
            "tm-debug", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = False
        self.set_doc = "DL debug mode set."
        self.show_doc = "The debugging option for DL is set to"

dl_debug = DLDebug()


class DLStop(Parameter):
    '''enable/disable debugging information for the DL commands'''
    def __init__(self):
        super(DLStop, self).__init__(
            "tm-stop", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = False
        self.set_doc = "DL stop at checkpoint set."
        self.show_doc = "The stop mode for DL is set to"

dl_stop = DLStop()


class DLMode(Parameter):
    '''select the mode of operation of TM'''
    def __init__(self):
        super(DLMode, self).__init__(
            "tm-mode", COMMAND_OBSCURE, PARAM_ENUM, ["normal", "restart"])
        self.value = "normal"
        self.set_doc = "DL mode of operation. Values: {normal, restart}."
        self.show_doc = "The mode of operation for DL is set to"

dl_mode = DLMode()


class DLHBreak(Parameter):
    '''select whether to use hardware breakpoints provided by kdl.'''
    def __init__(self):
        super(DLHBreak, self).__init__(
            "tm-hbreak", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = False
        self.set_doc = "DL set hardware breakpoints to take a checkpoint."
        self.show_doc = "TM: hardware breakpointing '{}'"

    def get_set_string(self):
        if not self.value and KDLUtil.is_kdl_initialized():
            ret = KDLUtil.exec_cmd("dl_dropall_checkpoints()")
            if not ret or ret != 0:
                raise Exception("unable to delete HW breakpoints.")
        return self.show_doc.format("set" if self.value else "removed")

    def get_show_string(self, svalue):
        return self.show_doc.format("set" if self.value else "removed")

dl_hbreak = DLHBreak()


class DLSearch(Parameter):
    '''
    select which type of search algorithm should be used when
    performing the search.
    '''
    LINEAR = "linear"
    BINARY = "binary"

    def __init__(self):
        super(DLSearch, self).__init__(
            "tm-search", COMMAND_OBSCURE, PARAM_ENUM,
            [self.LINEAR, self.BINARY])
        self.value = self.BINARY
        self.set_doc = "TM: search algorithm set to '{}'"
        self.show_doc = "TM: search algorithm selected '{}'"

    def get_set_string(self):
        return self.set_doc.format(self.value)

    def get_show_string(self, svalue):
        return self.show_doc.format(svalue)

    def execute(self, cps, expr):
        cp = -1
        # When performing searches for multiple checkpoints, it is more
        # convenient to initialized the long-lived rollback tree.
        KDLUtil.search_start(cps)

        if self.value == self.LINEAR:
            cp = self.__linear__(cps, expr)
        elif self.value == self.BINARY:
            cp = self.__binary__(cps, expr)
        else:
            raise Exception("unrecognized search method")

        if cp == -1:
            KDLUtil.restore()
        else:
            success, _ = KDLUtil.rollback(cp)
            if not success:
                raise Exception()

        # If it was initialized, clean-up the long-lived rollback tree
        KDLUtil.search_stop(cps)

        return cp

    def __linear__(self, cps, expr):
        variables = KDLUtil.get_ondemand_vars(expr)
        for cp in cps:
            success, is_from_kdl = KDLUtil.rollback(cp, variables)
            if not success:
                raise Exception()

            if not dl_search_kdl.value and is_from_kdl:
                continue

            found = parse_and_eval(expr)
            if found:
                return cp
        return -1

    def __binary__(self, cps, expr):
        variables = KDLUtil.get_ondemand_vars(expr)

        min = 0
        max = len(cps) - 1
        last_found = None
        while min <= max:
            i = (min + max) // 2
            # Perform the rollback and do the evaluation of the provided
            # expression
            success, is_from_kdl = KDLUtil.rollback(cps[i], variables)
            if not success:
                raise Exception()

            if not dl_search_kdl.value and is_from_kdl:
                continue

            found = parse_and_eval(expr)
            # if we are looking at the last element and it is true, return
            # the checkpoint id related
            if found and min == max:
                return cps[i]
            # If we are still not looking at the last element,
            # continue the search
            if found and min < max:
                last_found = cps[i]
                max = i - 1
            if not found:
                min = i + 1

        # Search ended without returning. Either return the last element
        # that evaluated to true, or -1
        return last_found if last_found else -1

dl_search = DLSearch()


class DLOnDemandRollback(Parameter):
    '''
    select whether to use on-demand rollback when using "delorean for" or
    "delorean search".
    '''
    def __init__(self):
        super(DLOnDemandRollback, self).__init__(
            "tm-ondemand-rb", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = False
        self.set_doc = "TM: on-demand rollback {}."
        self.show_doc = "TM: on-demand rollback is {}"

    def get_set_string(self):
        return self.set_doc.format("enabled" if self.value else "disabled")

    def get_show_string(self, svalue):
        return self.show_doc.format("enabled" if svalue else "disabled")

dl_ondemand_rb = DLOnDemandRollback()


class DLCleanupMaps(Parameter):
    '''
    enables/disables the cleanup of the maps using automatic detection. This is
    meant to be used only for automatic testing/benchmarking purposes.
    '''
    def __init__(self):
        super(DLCleanupMaps, self).__init__(
            "tm-cleanup-maps", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = True
        self.set_doc = "TM: clean up maps {}."
        self.show_doc = "TM: clean up maps is {}"

    def get_set_string(self):
        return self.set_doc.format("enabled" if self.value else "disabled")

    def get_show_string(self, svalue):
        return self.show_doc.format("enabled" if svalue else "disabled")

dl_cleanup_maps = DLCleanupMaps()


class DLSearchSmmap(Parameter):
    '''enables/disables searching and looping over kdl checkpoints.'''
    def __init__(self):
        super(DLSearchSmmap, self).__init__(
            "tm-search-kdl", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = False
        self.set_doc = "TM: {} kdl checkpoint in searches."
        self.show_doc = "TM: kdl checkpoint is {} searches."

    def get_set_string(self):
        return self.set_doc.format("include" if self.value else "exclude")

    def get_show_string(self, svalue):
        return self.show_doc.format(
            "included in" if svalue else "excluded from")

dl_search_kdl = DLSearchSmmap()


class DLTrackRegs(Parameter):
    '''enables/disables the tracking and rolling-back of registers'''
    def __init__(self):
        super(DLTrackRegs, self).__init__(
            "tm-track-regs", COMMAND_OBSCURE, PARAM_BOOLEAN)
        self.value = True
        self.set_doc = "TM: tracks registers {}"
        self.show_doc = "TM: on-demand rollback is {}"

    def get_set_string(self):
        # update the configuration of kdl too, if possible
        KDLUtil.write_proc_files(
            KDLUtil.CONF_DIR, ["hwbp_skip_regs"], "0" if self.value else "1")
        return self.set_doc.format("enabled" if self.value else "disabled")

    def get_show_string(self, svalue):
        return self.show_doc.format("enabled" if svalue else "disabled")

dl_track_regs = DLTrackRegs()


###############################################################################
# DL General Prefixes
###############################################################################
class CmdPrefix(Command):
    '''generic prefix class'''
    def __init__(self, cmd):
        self._cmd = cmd
        super(CmdPrefix, self).__init__(
            self._cmd, COMMAND_OBSCURE, prefix=True)

    def invoke(self, arg, from_tty):
        print_error("'{}' must be followed by a sub-command".format(self._cmd))
        execute("help {}".format(self._cmd))


class DLPrefix(CmdPrefix):
    '''take memory checkpoints with TM.'''

    def __init__(self):
        super(DLPrefix, self).__init__("delorean")

DLPrefix()


class DLSetPrefix(CmdPrefix):
    '''set statistics and configurations for TM.'''

    def __init__(self):
        super(DLSetPrefix, self).__init__("set delorean")

DLSetPrefix()


class DLShowPrefix(CmdPrefix):
    '''show statistics and configurations of TM.'''

    def __init__(self):
        super(DLShowPrefix, self).__init__("show delorean")

DLShowPrefix()


class ResetPrefix(CmdPrefix):

    def __init__(self):
        super(ResetPrefix, self).__init__("reset")

ResetPrefix()


class DLResetPrefix(CmdPrefix):
    '''clear statistics and configurations for TM.'''

    def __init__(self):
        super(DLResetPrefix, self).__init__("reset delorean")

DLResetPrefix()


class DLInfoPrefix(CmdPrefix):
    '''obtain information about the checkpoints and othres.'''

    def __init__(self):
        super(DLInfoPrefix, self).__init__("info delorean")

DLInfoPrefix()


class DLDeletePrefix(CmdPrefix):

    def __init__(self):
        super(DLDeletePrefix, self).__init__("delete delorean")

DLDeletePrefix()


###############################################################################
# Checkpoint
###############################################################################
class DLCheckpointPrefix(CmdPrefix):
    '''manage checkpoints.'''

    def __init__(self):
        super(DLCheckpointPrefix, self).__init__("delorean checkpoint")

DLCheckpointPrefix()


class DLInit(Command):
    '''
    Initialise kdl on a specified memory area. This is useful only for
    testing purposes and is not ment to be used interactively.

    Command:
    delorean init <location> <size_in_bytes>
    '''
    def __init__(self):
        self._cmd = "delorean init"
        super(DLInit, self).__init__(
            self._cmd, COMMAND_OBSCURE, COMPLETE_LOCATION)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        match = search("(.+) (.+)", arg)
        if not match:
            print_error("wrong parameters")
            execute("help {}".format(self._cmd))
            return

        location = match.group(1)
        bsize = match.group(2)
        success = KDLUtil.kdl_init(location, bsize)
        if not success:
            raise Exception()

DLInit()


class DLCheckpointTake(Command):
    '''
    take a checkpoint. This command also provides the possibility to
    evaluate a condition to whether to take a checkpoint or not.

    Commands:
    delorean checkpoint take
    delorean checkpoint take <location>
    delorean checkpoint take <location> if <condition>
    '''

    def __init__(self):
        self._cmd = "delorean checkpoint take"
        super(DLCheckpointTake, self).__init__(
            self._cmd, COMMAND_OBSCURE, COMPLETE_LOCATION)

    def invoke(self, arg, from_tty):
        global cpb_counter

        if not arg:
            # issue the start for a new checkpoint interval
            success = KDLUtil.take_cp()
            if not success:
                raise Exception()
        else:
            match = search("(.+) if (.+)", arg)
            cpb_counter += 1
            if not dl_hbreak.value and match:
                cpbreaks[cpb_counter] = DLCheckpointExec(
                    cpb_counter, match.group(1), match.group(2), internal=True)
            elif dl_hbreak.value and match:
                cpbreaks[cpb_counter] = DLCheckpointExec(
                    cpb_counter, match.group(1), internal=True)
            else:
                cpbreaks[cpb_counter] = DLCheckpointExec(
                    cpb_counter, arg, internal=True)

DLCheckpointTake()


class DLCheckpointDelete(Command):
    '''delete the checkpoint with the specified ID.'''

    def __init__(self):
        super(DLCheckpointDelete, self).__init__(
            "delorean checkpoint delete", COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        global cpbreaks

        try:
            bp = cpbreaks.pop(int(arg), None)
        except ValueError:
            print_error("invalid checkpoint ID")
            return

        if not bp:
            print_error("unable to access checkpoint (ID={}).\n".format(arg))
            return

        success = KDLUtil.delete_breakpoint(bp)
        if not success:
            raise Exception()

    def complete(self, text, word):
        return (
            str(c) for c in list(cpbreaks.keys()) if str(c).startswith(text))

DLCheckpointDelete()


class DLDeleteCheckpoints(Command):
    '''delete all the checkpoints which are currently set.'''

    def __init__(self):
        super(DLDeleteCheckpoints, self).__init__(
            "delete delorean checkpoints", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        for bp in list(cpbreaks.values()):
            KDLUtil.delete_breakpoint(bp)
        cpbreaks.clear()

DLDeleteCheckpoints()


class DLInfoBreakpoints(Command):
    '''obtain information about set checkpoints'''

    def __init__(self):
        super(DLInfoBreakpoints, self).__init__(
            "info delorean breakpoints", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        if not cpbreaks:
            print_error("no breakpoints were set or taken")
            return

        write("{:>4} {:>10} {:>16} {:>50} {:>10}\n".format(
            "ID", "Type", "Address", "Where", "Condition"))
        for k, v in list(cpbreaks.items()):
            write("{:>4} {:>10} 0x{:<16X} {:>50} {:>10}\n".format(
                k, ("break" if not v.is_hw else "hw-break"),
                decode_line(v.location)[1][0].pc, v.location,
                (v.user_condition if v.user_condition else "--")))

DLInfoBreakpoints()


class DLInfoCheckpoints(Command):
    '''
    obtain information about the checkpoints already taken. It is also possible
    to specify a limit on the number of checkpoints shown. This will show only
    the n most recent checkpoints.

    Commands:
    info delorean checkpoints
    info delorean checkpoints <limit>
    '''

    def __init__(self):
        super(DLInfoCheckpoints, self).__init__(
            "info delorean checkpoints", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):

        # obtain the maximum ID
        info = KDLUtil.get_info()
        if not info:
            return
        max_id = info["max_cp_id"]
        limit = int(arg) if arg else max_id
        # collect the information for all the
        checkpoints_info = []
        max_id = (limit-1 if limit < max_id else max_id)
        for id in list(range(max_id, -1, -1)):
            info = KDLUtil.get_info(id)
            if info:
                checkpoints_info.append(info)
            else:
                return

        write("{:^4} {:^10} {:^10} {:^16} {:^16} {:^16} {:^16}\n".format(
            "ID", "Known", "From SMMAP", "PC", "EFLAGS", "BP", "SP"))
        for info in checkpoints_info:
            write(
                "{:<4} {:<10} {:^10} 0x{:<16x} 0x{:<16x} 0x{:<16x} "
                "0x{:<16x}\n".format(
                    info["cp_id"], not info["is_unknown"],
                    info["from_kdl"], info["regs"]["pc"],
                    info["regs"]["eflags"], info["regs"]["rbp"],
                    info["regs"]["rsp"]))

DLInfoCheckpoints()


class DLInfoStatus(Command):
    '''obtain information about set checkpoints'''

    def __init__(self):
        super(DLInfoStatus, self).__init__(
            "info delorean status", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        info = KDLUtil.get_info()
        if not info:
            return

        write("Status of the process under kdl:\n")
        if info["is_in_rollback"]:
            write("\t- Is in ROLLBACK\n")

        if info["is_unknown"]:
            write("NO INFO are available for this checkpoint\n")
        else:
            write("\t- Max checkpoint ID: {}\n".format(info["max_cp_id"]))
            write("\t- Checkpoint interval ID: {}\n".format(info["cp_id"]))
            write("\t- Checkpoint PC register: 0x{:x}\n".format(
                int(info["regs"]["pc"])))
            write("\t- Checkpoint from SMMAP: {}\n".format(
                info["from_kdl"]))

DLInfoStatus()


class DLCheckpointExec(Breakpoint):
    '''The breakpoint that actually executes the checkpoint'''

    def __init__(self, breakid, spec, condition=None, internal=False):
        super(DLCheckpointExec, self).__init__(spec, internal=internal)
        self.user_condition = condition
        self.breakid = breakid
        self.is_hw = False
        # if the inferior is already running, set the hardware breakpoint
        # immediately
        self.__set_hwbp__()

    def __kdl_init__(self):
        if not KDLUtil.is_kdl_initialized():
            print_info("Need to initialized kdl")
            success = KDLUtil.kdl_init()
            if not success:
                raise Exception()

    def __set_hwbp__(self):
        if not KDLUtil.is_proc_running():
            return False

        # if necessary, proceed with initialization
        self.__kdl_init__()
        # Set an hardware breakpoint, if possible
        ret = KDLUtil.exec_cmd("dl_set_checkpoint(0x{:x})".format(
            decode_line(self.location)[1][0].pc))
        if ret is None or int(ret) != 0:
            raise print_error("unable to set a hardware breakpoint")
            return True

        # Disable the GDB software breakpoint
        self.enabled = False
        self.is_hw = True
        if dl_hbreak.value and KDLUtil.is_proc_running():
            return dl_stop.value

    def stop(self):
        # In case kdl is not initialized, do so
        # NB: by design, this also initializes a new checkpoint interval
        #     hence we do not need to call 'dl_take_cp' when initializing
        self.__kdl_init__()

        # When hardware breakpoints are set, we replace gdb breakpoints with
        # hardware breakpoints. In this way, we have the advantage of fast
        # checkpoints in the kernel module while lazily initializing them.
        if dl_hbreak.value:
            return self.__set_hwbp__()

        # skip the checkpoint if a condition was provided and did not evaluate
        # to true.
        try:
            if self.user_condition and not parse_and_eval(self.user_condition):
                return False
        except error as e:
            print_error(
                "error on condition: {}; ignore condition".format(str(e)), True)
            self.user_condition = None

        # Take a checkpoint if possible.
        success = KDLUtil.take_cp()
        if not success:
            raise Exception()

        return dl_stop.value


class DLReset(Function):
    def __init__(self):
        super(DLReset, self).__init__("dl_reset")

    def invoke(self):
        global cpbreaks

        # clear checkpointing statistics
        KDLUtil.clear_all_stats()
        print_debug("cleared stats", exec_cb=KDLUtil.show_all_stats)

        # re-enable GDB breakpoints if we are using hardware breakpointing.
        # This is required only when using hardware breakpoints to provide a
        # seemless interface when switching from one type of breakpoint to
        # another.
        for bp in list(cpbreaks.values()):
            bp.enabled = True

        print_debug("kdl was reset")
        return ""

DLReset()


###############################################################################
# Rollback/Restart/Restore
###############################################################################
class DLRollback(Command):
    '''read-only rollback to the specified checkpoint ID.'''

    def __init__(self):
        super(DLRollback, self).__init__(
            "delorean rollback", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        success, _ = KDLUtil.rollback(arg)
        if not success:
            raise Exception()

DLRollback()


class DLRestore(Command):
    '''after a rollback, restore is used to move back to the "present".'''

    def __init__(self):
        super(DLRestore, self).__init__(
            "delorean restore", COMMAND_OBSCURE, COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        success = KDLUtil.restore()
        if not success:
            raise Exception()

DLRestore()


# Hook on the continue command that detects whether we are in
# rollback. If so, it forces a restore before continuing the execution.
# This hook is installed externally via the GDB script "tm.gdb".
class DLForceRestore(Function):
    def __init__(self):
        super(DLForceRestore, self).__init__("dl_force_restore")

    def invoke(self):
        if not KDLUtil.is_proc_running():
            print_debug("inferior not running; no need to check kdl state.")
            return ""

        if not KDLUtil.is_kdl_initialized():
            print_debug("kdl was not initialized; continuing..")
            return ""

        if KDLUtil.is_in_rollback():
            success = KDLUtil.restore()
            if not success:
                raise Exception()

            print_info("forced 'restore' from rollback state")
            return ""
        else:
            print_info("continuing")
            return ""

DLForceRestore()


###############################################################################
# Handle taken checkpoints: FOR .. {IF, IF-DO, DROP} and SEARCH
###############################################################################
class DLSearchCP(Command):
    '''
    Search for the first checkpoint which satisfies the condition. When using
    find with the binary search algorithm, the condition must evaluate to
    true from a point onwards.

    delorean search <condition>
    '''
    def __init__(self):
        super(DLSearchCP, self).__init__(
            "delorean search", COMMAND_OBSCURE, COMPLETE_LOCATION)

    def invoke(self, arg, from_tty):
        expr = arg
        max_id = KDLUtil.get_info()["max_cp_id"]
        if not max_id or max_id < 0:
            print_error(
                "unable to retrieve the max ID (err: {})".format(max_id))
            return

        # evaluate the condition provided so that we are sure that the
        # expression provided by the user is valid.
        try:
            KDLUtil.rollback(0)
            parse_and_eval(expr)
            KDLUtil.restore()
        except error:
            print_error(str(error))
            print_error("invalid condition provided")
            return

        # based on the condition and the algorithm requested, search for the
        # earliest checkpoint that satisfies the condition.
        # oldest checkpoint == highest id
        cps = list(range(max_id, -1, -1))
        cp = dl_search.execute(cps, expr)
        if (cp >= 0):
            print_info("found checkpoint (ID={})".format(cp))
        else:
            print_info("No checkpoint found which satisfies the condition")

DLSearchCP()


class DLFor(Command):
    '''
    handle taken checkpoints. This command supports several combinations,
    listed below. The identifier is described and specified using JSON.

    cp identifier: <cp arrays>|<intervals>|<mixed arrays>|all
        cp arrays: [id,id,..]
        intervals: (start_id, end_id)
        mixed arrays: [ cp ids and/or intervals ]

    delorean for <cp identifier> if <expr>
    delorean for <cp identifier> if <expr> do <commands>
    delorean for <cp identifier> do <commands>

    The semantic of the command is, in fact, a loop iterating over the
    specified checkpoint IDs.
    '''
    def __init__(self):
        super(DLFor, self).__init__("delorean for", COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        # parase the argument
        pattern = "(?P<specifier>.*?)\s+(?P<subcmd>(if|do)\s+.+)"
        match = search(pattern, arg)
        if not match:
            print_error("unable to parse the 'delorean for' sub-command")
            return

        # parse the specifier and retrieve a list of IDs
        ids = self.__parse_specs__(match)
        if not ids:
            return

        # select the command and the parameters
        subcmd, parameters = self.__parse_subcmd__(match)
        if not subcmd:
            print_error("no sub command selected")
            return

        subcmd(ids, *parameters)

    def __parse_specs__(self, match):
        specifier = match.group("specifier")
        # get the max checkpoint id and return a list of all the possible
        # checkpoint IDs
        if specifier == "all":
            max_id = KDLUtil.get_info()["max_cp_id"]
            if not max_id or max_id < 0:
                print_error(
                    "unable to retrieve the max ID (err: {})".format(max_id))
                return None

            return list(range(max_id, -1, -1))

        specs = eval(specifier)

        # Expand all intervals and flatten the array, if necessary
        ids = []
        if type(specs) == list:
            for spec in specs:
                if type(spec) == tuple:
                    ids.extend(list(range(spec[0], spec[1]+1)))
                elif type(spec) == int:
                    ids.append(spec)
                else:
                    print_error("unable to parse the checkpoint IDs specifier")
                    return None
        elif type(specs) == tuple:
            ids.extend(list(range(specs[0], specs[1]+1)))
        else:
            print_error("unable to parse the checkpoint IDs specifier")
            return None

        res = list(set(ids))
        res.sort(reverse=True)
        return res

    def __parse_subcmd__(self, match):
        def handle_if(subcmd):
            condexpr = None
            cmdexpr = None
            # locate the "do" if is in the string
            doindex = subcmd.find(" do ")
            if doindex > -1:
                i = doindex + 4
                cmdexpr = subcmd[i:]
            else:
                doindex = len(subcmd)
            # extract the if slice
            condexpr = subcmd[3:doindex]

            return (self.__if__, [condexpr, cmdexpr])

        def handle_do(subcmd):
            cmdexpr = subcmd[3:]
            return (self.__do__, [cmdexpr])

        try:
            subcmd = match.group("subcmd")
        except:
            print_error("unable to parse the sub-command")
            return (None, None)

        # Handle the if-command
        if subcmd.startswith("if "):
            return handle_if(subcmd)
        # Handle the do-command
        elif subcmd.startswith("do "):
            return handle_do(subcmd)

        # Handle an unknown command
        else:
            print_error("unable to parse the sub-command")
            return (None, None)

    def __if__(self, cps, condexpr, commands=None):
        positive_outcomes = []
        negative_outcomes = []

        if dl_ondemand_rb.value and commands:
            print_info(
                "on-demand rollback is currently not supported for "
                "command execution")
            return

        variables = KDLUtil.get_ondemand_vars(condexpr)

        # for efficiency reasons, use the long-lived rollback tree
        KDLUtil.search_start(cps)

        for cp in cps:
            success, is_from_kdl = KDLUtil.rollback(cp, variables)
            if not success:
                raise Exception()

            if not dl_search_kdl.value and is_from_kdl:
                continue

            outcome = parse_and_eval(condexpr)
            if outcome:
                positive_outcomes.append(cp)
                if commands:
                    print_info("Executing commands @cp={}".format(cp))
                    for command in commands.split(";"):
                        command = command.strip()
                        print_debug("executing '{}'".format(command))
                        execute(command)
            else:
                negative_outcomes.append(cp)

        # if we previously initialized the search tree, we need to explicitely
        # clean it up
        KDLUtil.search_stop(cps)

        # print statistics
        if positive_outcomes:
            print_info("checkpoints satisfying condition")
            print_info("\t{}".format(KDLUtil.list2specifier(positive_outcomes)))

        if negative_outcomes:
            print_info("checkpoints NOT satisfying condition")
            print_info("\t{}".format(KDLUtil.list2specifier(negative_outcomes)))

        # restore state
        success = KDLUtil.restore()
        if not success:
            raise Exception()

    def __do__(self, cps, commands):
        if dl_ondemand_rb.value and commands:
            print_info(
                "on-demand rollback is currently not supported for "
                "command execution")
            return

        # for efficiency reasons, use the long-lived rollback tree
        KDLUtil.search_start(cps)
        for cp in cps:
            success, is_from_kdl = KDLUtil.rollback(cp)
            if not success:
                raise Exception()

            if not dl_search_kdl.value and is_from_kdl:
                continue

            print_info("Executing commands @cp={}".format(cp))
            for command in commands.split(";"):
                command = command.strip()
                print_debug("executing '{}'".format(command))
                execute(command)

        KDLUtil.search_stop(cps)
        # restore state
        success = KDLUtil.restore()
        if not success:
            raise Exception()

DLFor()


###############################################################################
# Confs
###############################################################################
class DLShowConfs(Command):
    '''show the configurations of the KDL module.'''

    def __init__(self):
        self._cmd = "show delorean confs"
        super(DLShowConfs, self).__init__(self._cmd, COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        confs = (KDLUtil.list_proc_files(KDLUtil.CONF_DIR)
                 if arg == "all" else [arg])
        values = KDLUtil.read_proc_files(KDLUtil.CONF_DIR, confs)
        for value in values:
            write("\t{}: {}\n".format(value[0], value[1]))

    def complete(self, text, word):
        files = KDLUtil.list_proc_files(KDLUtil.CONF_DIR)
        return (c for c in files if c.startswith(text))

DLShowConfs()


class DLSetConfs(Command):
    def __init__(self):
        self._cmd = "set delorean confs"
        super(DLSetConfs, self).__init__(self._cmd, COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        (conf, value) = arg.split(" ")
        KDLUtil.write_proc_files(KDLUtil.CONF_DIR, [conf], value)

    def complete(self, text, word):
        files = KDLUtil.list_proc_files(KDLUtil.CONF_DIR, False, True)
        return (c for c in files if c.startswith(text))

DLSetConfs()


class DLResetConfs(Command):
    '''clear configurations about the state of the KDL module.'''
    def __init__(self):
        self._cmd = "reset delorean confs"
        super(DLResetConfs, self).__init__(self._cmd, COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        confs = (KDLUtil.list_proc_files(KDLUtil.CONF_DIR, is_write=True)
                 if arg == "all" else [arg])
        KDLUtil.write_proc_files(KDLUtil.CONF_DIR, confs, "0")

    def complete(self, text, word):
        files = KDLUtil.list_proc_files(KDLUtil.CONF_DIR, is_write=True)
        return (c for c in files if c.startswith(text))

DLResetConfs()


###############################################################################
# Stats
###############################################################################
class DLShowStats(Command):
    '''show statistics about the state of the KDL module.'''

    def __init__(self):
        self._cmd = "show delorean stats"
        super(DLShowStats, self).__init__(self._cmd, COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        stats = (KDLUtil.list_proc_files(KDLUtil.STATS_DIR)
                 if arg == "all" else [arg])
        values = KDLUtil.read_proc_files(KDLUtil.STATS_DIR, stats)
        for value in values:
            write("\t{}: {}\n".format(value[0], value[1]))

    def complete(self, text, word):
        files = KDLUtil.list_proc_files(KDLUtil.STATS_DIR)
        return (s for s in files if s.startswith(text))

DLShowStats()


class DLResetStats(Command):
    '''clear statistics about the state of the KDL module.'''
    def __init__(self):
        self._cmd = "reset delorean stats"
        super(DLResetStats, self).__init__(self._cmd, COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        if not arg:
            execute("help {}".format(self._cmd))
            return

        stats = (KDLUtil.list_proc_files(KDLUtil.STATS_DIR, is_write=True)
                 if arg == "all" else [arg])
        KDLUtil.write_proc_files(KDLUtil.STATS_DIR, stats, "0")

    def complete(self, text, word):
        files = KDLUtil.list_proc_files(KDLUtil.STATS_DIR, is_write=True)
        return (s for s in files if s.startswith(text))

DLResetStats()

###############################################################################
# Aliases
###############################################################################
execute("alias -a dl = delorean")
execute("alias -a delete dl = delete delorean")
execute("alias -a info dl = info delorean")
execute("alias -a show dl = show delorean")
execute("alias -a set dl = set delorean")
execute("alias -a reset dl = reset delorean")
