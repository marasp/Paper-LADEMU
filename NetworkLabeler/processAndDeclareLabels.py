import json
import json
import os
from datetime import datetime

import pyshark
import pytz


def label_background_benign(pcap_in_file, vic_ip, att_ip, comments_in_file, reportfile, bk_ips):
    cap = pyshark.FileCapture(pcap_in_file, use_json=True)
    interesting_ips = [vic_ip, att_ip]
    background_ips = bk_ips
    interesting_packets = []
    benign_packets = []
    background_packets = []  # pyshark.packet.packet.Packet
    background_protocols = ['mdns', 'igmp', 'nbns', 'smb2', 'ldap', 'browser', 'ntp', 'cldap', 'kink', 'dhcp', 'ssdp',
                            'dcerpc', 'nbss', 'smb2', 'llmnr', 'arp', 'icmpv6', 'icmp']

    write_commentfile = open(comments_in_file, "w")
    print(f'## Starting to loop through the file {pcap_in_file} and write background and benign to file.')
    os.system('sleep 5')

    total_num_packets = 0
    for c in cap:
        total_num_packets += 1
        try:
            if (c.ip.src in interesting_ips) and (c.ip.dst in interesting_ips) and (c.ip.src != c.ip.dst):
                interesting_packets.append(c)
                print(total_num_packets)  # for debugging
                write_commentfile.write("-a {}:{} \n".format(c.frame_info.number, "T1071.001")) # C2

            elif (c.layers.__getitem__(-1)._layer_name in background_protocols) or (not c.ip.addr):
                background_packets.append(c)
                print(total_num_packets)
                write_commentfile.write("-a {}:{} \n".format(c.frame_info.number, "Background"))  # background traffic

            elif (c.ip.src in background_ips) and (c.ip.dst in background_ips):
                background_packets.append(c)
                print(total_num_packets)  # for debugging
                write_commentfile.write(
                    "-a {}:{} \n".format(c.frame_info.number, "Background"))  # GHOSTS background traffic between VMs

            else:
                benign_packets.append(c)
                #print(total_num_packets)  # for debugging
                write_commentfile.write("-a {}:{} \n".format(c.frame_info.number, "Benign"))  # GHOSTS web trafffic

        except AttributeError:
            pass

    print(f'## Done. \n{pcap_in_file} contains {total_num_packets} packets in total:')
    print(f'Number of interesting(attacker/victim) packets: {(len(interesting_packets))}')
    print(f'Number of background-traffic packets: {(len(background_packets))}')
    print("**********")

    ###############################################################
    
    print("Now on to the Caldera report!")
    os.system('sleep 5')
    # Read Caldera report:

    with open(reportfile, "r") as f:
        data = json.load(f)

    agent_name = {}

    for x in data["steps"]:
        agent_name[x] = data['steps'][x]
        agent_name = x  # for reading different reports, agent name changes

    innersteps = data["steps"][agent_name]["steps"]
    num_packets_in_attacks = 0
    caldera_packets = []

    for a in innersteps:
        try:
            start_time_obj = datetime.strptime(a['agent_reported_time'], "%Y-%m-%d %H:%M:%S").isoformat()
            end_time_obj = datetime.strptime(a["run"], "%Y-%m-%d %H:%M:%S").isoformat()
        except KeyError:
            print(a["attack"]["technique_id"])
            exit(0)
        except TypeError:
            print(a["attack"]["technique_id"])
            exit(0)

        for t in interesting_packets:
            p_time = t.sniff_time.strftime("%Y-%m-%d %H:%M:%S")

            # Handling timezones with pytz:
            local = pytz.timezone('Europe/Vienna')
            naive = datetime.strptime(p_time, "%Y-%m-%d %H:%M:%S")
            local_dt = local.localize(naive, is_dst=None)
            date_time_obj = local_dt.astimezone(pytz.utc).isoformat().split('+')[0]

            while start_time_obj <= date_time_obj <= end_time_obj: # Finding packets within attack range.
                num_packets_in_attacks += 1
                write_commentfile.write("-a {}:{} \n".format(t.frame_info.number, a["attack"]["technique_id"]))
                caldera_packets.append(t)  # add caldera packets for summarize in the end
                break

        if (len(caldera_packets) <= 1):
            print('*Some* of the steps in the CALDERA report were not processed correctly. Please check if the report needs some more processing first.')

    print(f'Found {(len(caldera_packets))} packets related to attacks in the Caldera report.')
    write_commentfile.close()
    os.system('sleep 5')
    return

