(() => {
    logger.log("stage_js_loader");

    const MAXSIZE = 256 * 1024;

    const sockaddr_in = malloc(16);
    const addrlen = malloc(8);
    const enable = malloc(4);
    const len_ptr = malloc(8);
    const payload_buf = malloc(MAXSIZE);

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

    function create_socket() {
        // Clear sockaddr
        for (let i = 0; i < 16; i++) write8_uncompressed(sockaddr_in + BigInt(i), 0);

        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("Socket creation failed: " + toHex(sock_fd));
        }

        write32_uncompressed(enable, 1);
        syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

        write8_uncompressed(sockaddr_in + 1n, AF_INET);
        write16_uncompressed(sockaddr_in + 2n, 0);        // port 0
        write32_uncompressed(sockaddr_in + 4n, 0);        // INADDR_ANY

        const bind_ret = syscall(SYSCALL.bind, sock_fd, sockaddr_in, 16n);
        if (bind_ret === 0xffffffffffffffffn) {
            syscall(SYSCALL.close, sock_fd);
            throw new Error("Bind failed: " + toHex(bind_ret));
        }

        const listen_ret = syscall(SYSCALL.listen, sock_fd, 3n);
        if (listen_ret === 0xffffffffffffffffn) {
            syscall(SYSCALL.close, sock_fd);
            throw new Error("Listen failed: " + toHex(listen_ret));
        }

        return sock_fd;
    }

    function get_port(sock_fd) {
        write32_uncompressed(len_ptr, 16);
        syscall(SYSCALL.getsockname, sock_fd, sockaddr_in, len_ptr);

        const port_be = read16_uncompressed(sockaddr_in + 2n);
        return Number(((port_be & 0xFFn) << 8n) | ((port_be >> 8n) & 0xFFn));
    }

    function setup_socket_until_port_50000() {
        let sock_fd = null;
        let port = 0;
        let attempts = 0;
        const MAX_ATTEMPTS = 60000;

        let last_sock = null;
        let last_port = 0;

        while (port !== 50000 && attempts < MAX_ATTEMPTS) {
            try {
                sock_fd = create_socket();
            } catch (err) {
                attempts++;
                continue;
            }

            port = get_port(sock_fd);

            last_sock = sock_fd;
            last_port = port;

            if (port !== 50000) {
                syscall(SYSCALL.close, sock_fd);
            }

            attempts++;
        }

        if (port !== 50000) {
            if (last_sock !== null) {
                logger.log("stage_remote_js_loader: warning: did not get port 50000 after " + attempts + " attempts; using last assigned port " + last_port);
                return { sock_fd: last_sock, port: last_port };
            } else {
                throw new Error("Failed to create any socket after " + attempts + " attempts");
            }
        }

        return { sock_fd, port };
    }

    function recreate_socket() {
        const sock_fd = create_socket();
        const port = get_port(sock_fd);

        const current_ip = get_current_ip();
        if (current_ip === null) {
            send_notification("No network available!\nAborting...");
            throw new Error("No network available!\nAborting...");
        }

        const network_str = current_ip + ":" + port;
        logger.log("stage_remote_js_loader: socket recreated on " + network_str);
        send_notification("Remote JS Loader\nListening on " + network_str);

        return { sock_fd, port, network_str };
    }

    // Initial setup (retry until port 50000, but fall back to last random port if attempts exhausted)
    let { sock_fd, port } = setup_socket_until_port_50000();

    const current_ip = get_current_ip();
    if (current_ip === null) {
        send_notification("No network available!\nAborting...");
        throw new Error("No network available!\nAborting...");
    }

    let network_str = current_ip + ":" + port;
    logger.log("stage_remote_js_loader: listening on " + network_str);
    send_notification("Remote JS Loader\nListening on " + network_str);

    function bytes_to_string(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i++)
            s += String.fromCharCode(bytes[i]);
        return s;
    }

    var exit_js_loader = false;
    while (!exit_js_loader) {
        try {
            logger.log("stage_remote_js_loader: awaiting connection at " + network_str);

            write32_uncompressed(addrlen, 16);
            const client_fd = syscall(SYSCALL.accept, sock_fd, sockaddr_in, addrlen);

            if (client_fd === 0xffffffffffffffffn) {
                // logger.log("accept() failed: " + toHex(client_fd) + " - recreating socket");
                syscall(SYSCALL.close, sock_fd);

                const recreated = recreate_socket();
                sock_fd = recreated.sock_fd;
                port = recreated.port;
                network_str = recreated.network_str;
                continue;
            }

            logger.log("stage_remote_js_loader: client connected, fd: " + Number(client_fd));

            let total_read = 0;
            let read_error = false;

            while (total_read < MAXSIZE) {
                const bytes_read = syscall(
                    SYSCALL.read,
                    client_fd,
                    payload_buf + BigInt(total_read),
                    BigInt(MAXSIZE - total_read)
                );

                const n = Number(bytes_read);

                if (n === 0) break;
                if (n < 0) {
                    logger.log("read() error: " + n);
                    read_error = true;
                    break;
                }

                total_read += n;
                // logger.log("Read " + n + " bytes");
            }

            // logger.log("stage_remote_js_loader: finished reading, total=" + total_read + " error=" + read_error);

            if (read_error || total_read === 0) {
                logger.log("stage_remote_js_loader: no valid data received");
                syscall(SYSCALL.close, client_fd);
                continue;
            }

            const bytes = new Uint8Array(total_read);
            for (let i = 0; i < total_read; i++) {
                bytes[i] = Number(read8_uncompressed(payload_buf + BigInt(i)));
            }

            const js_code = bytes_to_string(bytes);

            write32_uncompressed(enable, 1);
            syscall(SYSCALL.setsockopt, client_fd, SOL_SOCKET, 0x800n, enable, 4n);
            _log_socket_fd = client_fd;

            logger.log("stage_remote_js_loader: executing payload...");
            try {
                eval(js_code);
                logger.log("stage_remote_js_loader: executed successfully");
                if (exit_js_loader) {
                    logger.log("stage_remote_js_loader: exit requested");
                }
            } finally {
                _log_socket_fd = null;
                syscall(SYSCALL.close, client_fd);
            }
        } catch (e) {
            logger.log("stage_remote_js_loader: ERROR in accept loop: " + e.message);
            logger.log(e.stack);
        }
    }
})()