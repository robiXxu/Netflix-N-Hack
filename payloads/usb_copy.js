(function() {

    function copy_usb_file(src_path, dst_path, remount_rw) {
        const MNT_UPDATE = 0x10000n;
        const MNT_RDONLY = 0x1n;

        function resolve_path(name) {
            if (name.charAt(0) === '/') return name;
            for (let u = 0; u < 8; u++) {
                if (usb_is_mounted(u)) return "/mnt/usb" + u + "/" + name;
            }
            throw new Error("no USB drive mounted");
        }

        src_path = resolve_path(src_path);
        dst_path = resolve_path(dst_path);

        if (!file_exists(src_path)) {
            logger.log("usb_copy: " + src_path + " not found");
            return;
        }

        let niov = 0n;
        let iov = 0n;
        let mounted_rw = false;
        if (remount_rw) {
            try {
                const iov_entries = [
                    ["from",      "/dev/ssd0.system_ex"],
                    ["fspath",    "/system_ex"],
                    ["fstype",    "exfatfs"],
                    ["large",     "yes"],
                    ["timezone",  "static"],
                    ["async",     null],
                    ["ignoreacl", null],
                ];
                niov = BigInt(iov_entries.length * 2);
                iov  = malloc(Number(niov) * 16);
                let iov_off = 0n;
                for (const [key, val] of iov_entries) {
                    const kp = alloc_string(key);
                    write64_uncompressed(iov + iov_off,      kp);
                    write64_uncompressed(iov + iov_off + 8n, BigInt(key.length + 1));
                    iov_off += 16n;
                    if (val !== null) {
                        const vp = alloc_string(val);
                        write64_uncompressed(iov + iov_off,      vp);
                        write64_uncompressed(iov + iov_off + 8n, BigInt(val.length + 1));
                    } else {
                        write64_uncompressed(iov + iov_off,      0n);
                        write64_uncompressed(iov + iov_off + 8n, 0n);
                    }
                    iov_off += 16n;
                }
                const r1 = syscall(SYSCALL.nmount, iov, niov, MNT_UPDATE);
                if (r1 === 0xffffffffffffffffn) {
                    logger.log("usb_copy: nmount RW failed: " + get_error_string());
                } else {
                    mounted_rw = true;
                }
            } catch (e) {
                logger.log("usb_copy: nmount RW error: " + e.message);
            }
        }

        try {
            logger.log("usb_copy: " + src_path + " -> " + dst_path);
            const dest_dir = dst_path.substring(0, dst_path.lastIndexOf('/'));
            syscall(SYSCALL.mkdir, alloc_string(dest_dir), 0x1ffn);
            const n = copy_file(src_path, dst_path);
            const stat_buf = malloc(0x100);
            const dst_fd = syscall(SYSCALL.open, alloc_string(dst_path), O_RDONLY);
            let verified = false;
            if (dst_fd !== 0xffffffffffffffffn) {
                if (syscall(SYSCALL.fstat, dst_fd, stat_buf) === 0n) {
                    const dst_size = Number(read64_uncompressed(stat_buf + 0x48n));
                    verified = (dst_size === n);
                    logger.log("usb_copy: ok (" + n +
                        " bytes, on disk " + dst_size + (verified ? " verified)" : " MISMATCH)"));
                }
                syscall(SYSCALL.close, dst_fd);
            }
            if (!verified) {
                logger.log("usb_copy: ok (" + n + " bytes, verify skipped)");
            }
            send_notification("usb_copy OK: " + src_path);
        } catch(e) {
            logger.log("usb_copy: failed: " + e.message);
            send_notification("usb_copy failed");
        } finally {
            if (mounted_rw) {
                const r2 = syscall(SYSCALL.nmount, iov, niov, MNT_UPDATE | MNT_RDONLY);
                if (r2 === 0xffffffffffffffffn) {
                    logger.log("usb_copy: WARNING nmount RO failed: " + get_error_string());
                } else {
                    logger.log("usb_copy: remounted RO");
                }
            }
        }
    }

    // Copy jobs
    copy_usb_file("download0.dat", "/user/download/PPSA01650/download0.dat");
    // copy_usb_file("bdjstack.jar", "/system_ex/app/NPXS40140/cdc/bdjstack.jar", true);
})();
