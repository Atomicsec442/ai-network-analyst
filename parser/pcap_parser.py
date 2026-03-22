"""
pcap_parser.py
--------------
PCAP Parser Module for AI Network Analyst
------------------------------------------
This module uses tshark (Wireshark's CLI tool) to parse .pcap files.
It extracts:
  - DNS queries and responses
  - Source/Destination IPs
  - Query types (A, AAAA, TXT, MX, etc.)
  - DNS response codes (NXDOMAIN, SERVFAIL, etc.)
  - General packet/flow metadata

Output: Structured Python dict (JSON-serializable)

Usage:
    from parser.pcap_parser import PCAPParser
    parser = PCAPParser("samples/test.pcap")
    result = parser.parse()
"""

import subprocess
import json
import logging
import os
from typing import Optional

# Set up module-level logger
logger = logging.getLogger(__name__)


class PCAPParser:
    """
    Parses a PCAP file using tshark and extracts DNS and flow data.

    Args:
        pcap_path (str): Path to the .pcap file to analyze.
        tshark_path (str): Path to tshark binary (default: 'tshark' from PATH).
    """

    # DNS response code mapping (rcode integer → human-readable string)
    DNS_RCODES = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        8: "NXRRSet",
        9: "NOTAUTH",
        10: "NOTZONE",
    }

    # DNS query type mapping (qtype integer → label)
    DNS_QTYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    def __init__(self, pcap_path: str, tshark_path: str = "tshark"):
        self.pcap_path = pcap_path
        self.tshark_path = tshark_path
        self._validate_inputs()

    def _validate_inputs(self):
        """Check that the PCAP file exists and tshark is available."""
        if not os.path.isfile(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        result = subprocess.run(
            [self.tshark_path, "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise EnvironmentError(
                "tshark not found or not working. "
                "Install Wireshark/tshark and ensure it's in your PATH."
            )
        logger.debug("tshark found and working.")

    def _run_tshark(self, extra_args: list = None) -> str:
        """
        Run tshark on the PCAP file and return raw JSON output.

        Args:
            extra_args: Additional tshark arguments (filters, fields, etc.)

        Returns:
            Raw stdout string from tshark.
        """
        cmd = [
            self.tshark_path,
            "-r", self.pcap_path,   # Read from file
            "-T", "json",            # Output as JSON
            "-n",                    # Disable name resolution (faster)
        ]
        if extra_args:
            cmd.extend(extra_args)

        logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout for large files
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError("tshark timed out processing the PCAP file.")

        if result.returncode != 0:
            logger.warning(f"tshark stderr: {result.stderr}")

        return result.stdout

    def _parse_dns_packet(self, packet: dict) -> Optional[dict]:
        """
        Extract DNS-specific fields from a single tshark JSON packet.

        Args:
            packet: A single packet dict from tshark JSON output.

        Returns:
            Structured DNS record dict, or None if not a DNS packet.
        """
        try:
            layers = packet.get("_source", {}).get("layers", {})

            # Must have DNS layer to be relevant
            if "dns" not in layers:
                return None

            dns = layers["dns"]
            ip = layers.get("ip", {})
            frame = layers.get("frame", {})

            # --- Extract basic IP info ---
            src_ip = ip.get("ip.src", "unknown")
            dst_ip = ip.get("ip.dst", "unknown")
            timestamp = frame.get("frame.time_epoch", "0")

            # --- DNS flags ---
            # dns.flags.response: "0" = query, "1" = response
            is_response = dns.get("dns.flags.response", "0") == "1"

            # --- Response code (rcode) ---
            rcode_raw = dns.get("dns.flags.rcode", "0")
            try:
                rcode_int = int(rcode_raw)
            except (ValueError, TypeError):
                rcode_int = -1
            rcode_str = self.DNS_RCODES.get(rcode_int, f"UNKNOWN({rcode_int})")

            # --- Extract queries ---
            queries = []
            # tshark may represent multiple queries as a list or single dict
            raw_queries = dns.get("dns.qry.name", [])
            raw_qtypes = dns.get("dns.qry.type", [])

            if isinstance(raw_queries, str):
                raw_queries = [raw_queries]
            if isinstance(raw_qtypes, str):
                raw_qtypes = [raw_qtypes]

            for i, qname in enumerate(raw_queries):
                qtype_raw = raw_qtypes[i] if i < len(raw_qtypes) else "1"
                try:
                    qtype_int = int(qtype_raw)
                except (ValueError, TypeError):
                    qtype_int = 1
                qtype_str = self.DNS_QTYPES.get(qtype_int, f"TYPE{qtype_int}")
                queries.append({
                    "name": qname,
                    "type": qtype_str,
                    "type_id": qtype_int
                })

            # --- Extract answers (only for responses) ---
            answers = []
            if is_response:
                raw_answers = dns.get("dns.resp.name", [])
                raw_answers_data = dns.get("dns.a", [])  # A record IPs

                if isinstance(raw_answers, str):
                    raw_answers = [raw_answers]
                if isinstance(raw_answers_data, str):
                    raw_answers_data = [raw_answers_data]

                for ans_name in raw_answers:
                    answers.append({"name": ans_name})

                for ip_ans in raw_answers_data:
                    answers.append({"resolved_ip": ip_ans})

            return {
                "timestamp": float(timestamp),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "is_response": is_response,
                "rcode": rcode_str,
                "rcode_id": rcode_int,
                "queries": queries,
                "answers": answers,
                "transaction_id": dns.get("dns.id", "unknown"),
            }

        except Exception as e:
            logger.debug(f"Failed to parse DNS packet: {e}")
            return None

    def _parse_flow_packet(self, packet: dict) -> Optional[dict]:
        """
        Extract basic flow (IP/port) information from a packet.

        Args:
            packet: A single packet dict from tshark JSON output.

        Returns:
            Structured flow dict, or None if insufficient data.
        """
        try:
            layers = packet.get("_source", {}).get("layers", {})
            ip = layers.get("ip", {})
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            frame = layers.get("frame", {})

            src_ip = ip.get("ip.src")
            dst_ip = ip.get("ip.dst")

            if not src_ip or not dst_ip:
                return None  # Skip non-IP packets (e.g., ARP)

            # Determine protocol and ports
            if tcp:
                protocol = "TCP"
                src_port = int(tcp.get("tcp.srcport", 0))
                dst_port = int(tcp.get("tcp.dstport", 0))
                flags = tcp.get("tcp.flags.string", "")
            elif udp:
                protocol = "UDP"
                src_port = int(udp.get("udp.srcport", 0))
                dst_port = int(udp.get("udp.dstport", 0))
                flags = ""
            else:
                protocol = ip.get("ip.proto", "OTHER")
                src_port = 0
                dst_port = 0
                flags = ""

            return {
                "timestamp": float(frame.get("frame.time_epoch", 0)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_flags": flags,
                "length": int(frame.get("frame.len", 0)),
            }

        except Exception as e:
            logger.debug(f"Failed to parse flow packet: {e}")
            return None

    def parse(self) -> dict:
        """
        Main entry point. Parses the PCAP and returns structured data.

        Returns:
            dict with keys:
                - 'dns_records': list of DNS events
                - 'flows': list of network flows
                - 'summary': high-level packet counts
                - 'pcap_file': path to the source file
        """
        logger.info(f"Parsing PCAP: {self.pcap_path}")

        # Run tshark and get JSON
        raw_output = self._run_tshark()

        if not raw_output.strip():
            logger.warning("tshark returned empty output.")
            return self._empty_result()

        # Parse the JSON array of packets
        try:
            packets = json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            return self._empty_result()

        logger.info(f"Total packets loaded: {len(packets)}")

        dns_records = []
        flows = []

        # Process each packet
        for packet in packets:
            # Try DNS extraction
            dns_record = self._parse_dns_packet(packet)
            if dns_record:
                dns_records.append(dns_record)

            # Try flow extraction
            flow = self._parse_flow_packet(packet)
            if flow:
                flows.append(flow)

        # Build summary stats
        summary = {
            "total_packets": len(packets),
            "dns_packets": len(dns_records),
            "flow_packets": len(flows),
            "dns_queries": sum(1 for r in dns_records if not r["is_response"]),
            "dns_responses": sum(1 for r in dns_records if r["is_response"]),
            "nxdomain_count": sum(1 for r in dns_records if r["rcode"] == "NXDOMAIN"),
            "servfail_count": sum(1 for r in dns_records if r["rcode"] == "SERVFAIL"),
        }

        logger.info(f"Parse complete. DNS: {len(dns_records)}, Flows: {len(flows)}")

        return {
            "pcap_file": self.pcap_path,
            "summary": summary,
            "dns_records": dns_records,
            "flows": flows,
        }

    def _empty_result(self) -> dict:
        """Return an empty result structure on failure."""
        return {
            "pcap_file": self.pcap_path,
            "summary": {
                "total_packets": 0,
                "dns_packets": 0,
                "flow_packets": 0,
                "dns_queries": 0,
                "dns_responses": 0,
                "nxdomain_count": 0,
                "servfail_count": 0,
            },
            "dns_records": [],
            "flows": [],
        }
