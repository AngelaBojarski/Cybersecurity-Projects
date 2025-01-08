import sys
import port_scanner
import os_fingerprint

def main():
    if len(sys.argv) != 3:
        print("Usage: python scanner_main.py <subnet> <mask>")
        sys.exit(1)

    subnet = sys.argv[1]
    mask = int(sys.argv[2])

    live_hosts = port_scanner.ping_sweep(subnet, str(mask))
    print("Ping sweep completed.\n")

    for host in live_hosts:
        open_ports = port_scanner.port_scan(host, list(range(1, 1024)))
        print(f"Open ports on host {host}: {open_ports}\n")

        for port in open_ports:
            host_infos = os_fingerprint.scan_host(host, str(port))
            for host_info in host_infos:
                os_fingerprint.output_to_csv("scan_results.csv", host_info)
                print("\nScan results:")
                for k, v in host_info.items():
                    print(f"{k}: {v}")
                print()

if __name__ == "__main__":
    main()