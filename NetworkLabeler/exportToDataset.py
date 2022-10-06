import os


def export_to_json(labeled_attack_pcap):
    print("Will now start to export the PCAP to JSON-file.")

    basename = labeled_attack_pcap.split(".pcapng")[0]
    json_export_file = basename + ".json"

    try:
        os.system(f'tshark -r {labeled_attack_pcap} -l -n -T json > {json_export_file}')
        print("The network logfile was successfully written as dataset in JSON format.")
        return json_export_file

    except FileNotFoundError:
        print(f'There was no file with the name {labeled_attack_pcap}.\n')

def export_to_csv(labeled_attack_pcap):
    print("Will now start to export the PCAP to CSV-file.")

    basename = labeled_attack_pcap.split(".pcapng")[0]
    csv_export_file = basename + ".csv"

    try:
        # specify which columns to include. Can be added or removed as the user wishes.
        os.system(f'tshark -r {labeled_attack_pcap} -T fields -e frame.number -e frame.encap_type -e frame.time -e frame.time_epoch -e frame.time_relative -e frame.len -e frame.protocols -e frame.comment -e eth.dst -e eth.src -e eth.type -e ip.hdr_len -e ip.dsfield -e ip.len -e ip.id -e ip.flags -e ip.ttl -e ip.proto -e ip.checksum -e ip.checksum.status -e ip.src -e ip.addr -e ip.src_host -e ip.dst -e ip.dst_host -e tcp.srcport -e tcp.dstport -e tcp.port -e tcp.stream -e tcp.completeness -e tcp.len -e tcp.seq -e tcp.seq_raw -e tcp.nxtseq -e tcp.ack -e tcp.ack_raw -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.checksum -e tcp.checksum.status -e tcp.urgent_pointer -e tcp.analysis -e tcp.analysis.bytes_in_flight -e tcp.analysis.push_bytes_sent -e tcp.payload -e tcp.segment_data -e tcp.segments -e tcp.segments -e tcp.segment.count -e tcp.reassembled.length -e udp.srcport -e udp.dstport -e udp.port -e udp.length -e udp.checksum -e udp.checksum.status -e udp.stream -e http.connection -e http.request.line -e http.content_type -e http.content_encoding -e http.user_agent -e http.content_length_header -e http.host -e http.request -e http.request_number -e _ws.col.Info -E header=y -E separator="|" > {csv_export_file}')
        print("The network logfile was successfully written as dataset in CSV format.")
        return csv_export_file

    except FileNotFoundError:
        print(f'There was no file with the name {labeled_attack_pcap}.\n')
