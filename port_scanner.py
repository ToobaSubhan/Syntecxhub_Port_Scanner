import argparse
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ---------- Setup helpers ----------

def setup_logging(log_file):
    """Send log messages to the screen and to a file."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def parse_ports(text):
    """
    Turn text like "80", "1-100" or "22,80,443" into a sorted list of ports.
    Raises ValueError if the text is wrong or a port is not in 1-65535.
    """
    ports = set()

    for part in text.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:  # allow "100-50" too
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    bad_ports = [p for p in ports if p < 1 or p > 65535]
    if bad_ports:
        raise ValueError(f"ports must be between 1 and 65535, got: {bad_ports[:5]}")
    if not ports:
        raise ValueError("no ports given")

    return sorted(ports)


def find_ip(host):
    """Turn a host name (like scanme.nmap.org) into an IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise RuntimeError(f"Could not find the host '{host}'. Check the spelling.")


# ---------- Checking one port ----------

def service_name(port):
    """Return the usual service name for a port number (only a guess)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def get_banner(sock):
    """
    Read the banner from a connected socket.

    Some services (SSH, FTP, SMTP) talk first, so we just listen.
    Web servers stay quiet until asked, so if we hear nothing
    we send a tiny HTTP request and read the answer.
    Returns one line of text, or "" if we got nothing.
    """
    sock.settimeout(2)
    data = b""

    # First, just listen for a moment
    try:
        data = sock.recv(1024)
    except OSError:
        pass

    # Heard nothing? Ask like a web browser would
    if not data:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
        except OSError:
            pass

    text = data.decode(errors="ignore").strip()
    if not text:
        return ""

    lines = text.splitlines()

    # For web servers, the "Server:" line is the useful one
    if text.startswith("HTTP/"):
        for line in lines:
            if line.lower().startswith("server:"):
                return line.strip()

    return lines[0]


def scan_port(ip, port, timeout):
    """
    Check one port. Returns (port, status, service, banner).
    status is "open", "closed", "filtered" or "error".
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return port, "closed", "", ""        # host said "no"
    except socket.timeout:
        return port, "filtered", "", ""      # host said nothing
    except OSError:
        return port, "error", "", ""         # e.g. network unreachable

    # If we get here, the connection worked, so the port is open
    with sock:
        banner = get_banner(sock)
    return port, "open", service_name(port), banner


# ---------- Running the whole scan ----------

def scan_all(ip, ports, threads, timeout):
    """Scan every port using a pool of threads. Returns results and time taken."""
    results = {"open": [], "closed": [], "filtered": [], "error": []}
    started = datetime.now()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        jobs = [pool.submit(scan_port, ip, port, timeout) for port in ports]

        for job in as_completed(jobs):
            port, status, service, banner = job.result()
            results[status].append((port, service, banner))

            if status == "open":
                logging.info("Port %d OPEN  | service: %s | banner: %s",
                             port, service, banner or "none")

    for status in results:
        results[status].sort()

    return results, datetime.now() - started


def compress(ports):
    """Turn [1,2,3,5,7,8] into '1-3, 5, 7-8'."""
    ranges = []
    start = prev = None
    for p in ports:
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            ranges.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = p
    if start is not None:
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ", ".join(ranges)


def show_summary(host, results, time_taken):
    """Print and log the final report."""
    logging.info("-" * 50)
    logging.info("Summary for %s", host)
    logging.info("-" * 50)

    if results["open"]:
        logging.info("Open ports (%d):", len(results["open"]))
        for port, service, banner in results["open"]:
            logging.info("  %-6d %-10s %s", port, service, banner or "no banner")
    else:
        logging.info("Open ports: none")

    filtered = [port for port, _, _ in results["filtered"]]
    logging.info("Closed ports:   %d", len(results["closed"]))
    logging.info("Filtered ports: %s", compress(filtered) if filtered else "none")
    if results["error"]:
        logging.info("Ports with errors: %d", len(results["error"]))
    logging.info("Time taken: %s", time_taken)
    logging.info("-" * 50)


# ---------- Program start ----------

def get_arguments():
    """Read the options given on the command line."""
    parser = argparse.ArgumentParser(description="A simple multithreaded TCP port scanner.")
    parser.add_argument("host", nargs="?",
                        help="host name or IP to scan (if left out, you will be asked)")
    parser.add_argument("-p", "--ports", default=None,
                        help="ports to scan, e.g. 80 or 1-1000 or 22,80,443 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="how many ports to check at once (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="seconds to wait for each port (default: 1.0)")
    parser.add_argument("--log-file", default="scan_results.log",
                        help="file to save results in (default: scan_results.log)")
    return parser.parse_args()


def main():
    args = get_arguments()

    # No host on the command line? Ask for it.
    if args.host is None:
        args.host = input("Enter target host (e.g. scanme.nmap.org): ").strip()
        answer = input("Enter port or range (e.g. 1-100, press Enter for 1-1024): ").strip()
        args.ports = answer or None

    ports_text = args.ports or "1-1024"

    setup_logging(args.log_file)

    if args.threads < 1 or args.timeout <= 0:
        logging.error("Threads must be at least 1 and timeout must be more than 0.")
        sys.exit(1)

    try:
        ports = parse_ports(ports_text)
    except ValueError as error:
        logging.error("Bad port input: %s", error)
        sys.exit(1)

    try:
        ip = find_ip(args.host)
        logging.info("Scanning %s (%s) - %d port(s), %d threads, %.1fs timeout",
                     args.host, ip, len(ports), args.threads, args.timeout)
        results, time_taken = scan_all(ip, ports, args.threads, args.timeout)
    except RuntimeError as error:
        logging.error(error)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.warning("Scan stopped by the user.")
        sys.exit(1)

    show_summary(args.host, results, time_taken)


if __name__ == "__main__":
    main()