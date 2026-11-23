"""Per-device share of encrypted application traffic in CIC IoT-DIAD 2024 benign captures (packet-based features).

Usage: python3 02_cic_transfer_protection.py <benign_dir> <out.csv>

Rule (fixed in advance):
  * Control-plane / discovery protocols are excluded: ARP, DNS, MDNS, LLMNR, SSDP, NTP, DHCP, BOOTP, ICMP, ICMPV6,
    STP, IGMP, LLC, EAPOL, NBNS, CDP, LLDP.
  * LAN discovery traffic on DISCOVERY_PORTS is excluded (revision 1, after inspecting port use; see PROTOCOL.md).
  * Only packets with payload_length > 0 count.
  * A packet is ENCRYPTED if highest_layer is TLS/DTLS/SSL/QUIC/SSH, or either port is a well-known encrypted port
    (443, 8443, 8883, 5684, 22, 993, 995, 853, 5061).
  * Otherwise it is counted as UNPROTECTED (cleartext or unidentified).
  * Share is payload-byte weighted. Only packets whose device_mac carries a device name (not a raw MAC) are used.
  * Devices with fewer than 200 qualifying packets are reported but not used for calibration.
"""
import sys, glob, os, re
import pyarrow.parquet as pq
import pandas as pd

CTRL = {"ARP", "DNS", "MDNS", "LLMNR", "SSDP", "NTP", "DHCP", "BOOTP", "ICMP", "ICMPV6", "STP", "IGMP", "LLC",
        "EAPOL", "NBNS", "CDP", "LLDP", "DHCPV6", "IGMPV3"}
ENC_LAYERS = {"TLS", "DTLS", "SSL", "QUIC", "SSH", "SSHV2"}
ENC_PORTS = {443, 8443, 8883, 5684, 22, 993, 995, 853, 5061, 8009}  # 8009: Google Cast v2 (TLS)
# LAN discovery broadcasts (Tuya 6666/6667, SADP/ONVIF 37020, WS-Discovery 3702, SSDP 1900, mDNS 5353, LLMNR 5355)
DISCOVERY_PORTS = {6666, 6667, 37020, 3702, 1900, 5353, 5355}
MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
COLS = ["device_mac", "highest_layer", "src_port", "dst_port", "payload_length"]

if __name__ == "__main__":
    src, outp = sys.argv[1:3]
    parts = []
    for f in sorted(glob.glob(os.path.join(src, "*.parquet"))):
        pf = pq.ParquetFile(f)
        for rg in range(pf.num_row_groups):
            t = pf.read_row_group(rg, columns=COLS).to_pandas()
            t = t[t.device_mac.notna() & ~t.device_mac.astype(str).str.match(MAC)]
            t = t[(t.payload_length > 0) & ~t.highest_layer.astype(str).str.upper().isin(CTRL)
                  & ~t.src_port.isin(DISCOVERY_PORTS) & ~t.dst_port.isin(DISCOVERY_PORTS)]
            enc = t.highest_layer.astype(str).str.upper().isin(ENC_LAYERS) | t.src_port.isin(ENC_PORTS) | t.dst_port.isin(ENC_PORTS)
            t = t.assign(enc_bytes=t.payload_length.where(enc, 0), enc_pkt=enc.astype(int))
            parts.append(t.groupby("device_mac").agg(pkts=("payload_length", "size"), bytes=("payload_length", "sum"),
                                                     enc_bytes=("enc_bytes", "sum"), enc_pkts=("enc_pkt", "sum")))
    g = pd.concat(parts).groupby(level=0).sum()
    g["enc_share_bytes"] = g.enc_bytes / g.bytes
    g["enc_share_pkts"] = g.enc_pkts / g.pkts
    g["calibration_use"] = g.pkts >= 200
    g.sort_values("pkts", ascending=False).to_csv(outp)
    print(g.sort_values("pkts", ascending=False).round(3).to_string())
