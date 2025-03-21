import pyshark
import pandas as pd
from collections import defaultdict

pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.width", 1000)
pd.set_option("display.colheader_justify", "left")
pd.set_option("display.expand_frame_repr", False)


'''======================================================PCAP PARSER========================================================================'''

def hex_ssid_to_string(hex_ssid):
    hex_str = hex_ssid.replace(":", "")
    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')

# def pcap_Parser(file):
#
#
#     captures = []
#     cap = pyshark.FileCapture(file, display_filter='wlan.fc.type_subtype == 0x08')

#     for packet in cap:
#         if 'wlan.mgt' in packet:
#             print("******* radiotap *******:", packet['radiotap'].field_names)
#             print("******* wlan_radio *******:", packet['wlan_radio'].field_names)
#             print("***** wlan.mgt *****:", packet['wlan.mgt'].field_names)
#             print("******* wlan *******:", packet['wlan'].field_names)
#             break
#
#     for packet in cap:
#         try:
#
#             if 'wlan.mgt' in packet:
#                 hex_ssid = getattr(packet['wlan.mgt'], 'wlan_ssid', 'Could not be found.')
#                 ssid = hex_ssid_to_string(hex_ssid)
#                 tsf = getattr(packet['wlan_radio'], 'end_tsf', 'Not available')
#             else:
#                 ssid = 'Not available'
#                 tsf = 'Not available'
#
#             bssid = getattr(packet['wlan'], 'bssid', 'Could not be found.')
#             ra = getattr(packet['wlan'], 'ra', 'Could not be found.')
#             ta = getattr(packet['wlan'], 'ta', 'Could not be found.')
#             type_subtype = getattr(packet['wlan'], 'fc_type_subtype', 'Could not be found.')
#             phy = getattr(packet['wlan_radio'], 'phy', 'Could not be found.')
#             # mcs_idx = getattr(packet['wlan_radio'], 'mcs_idx', 'Could not be found.')
#             # bandwidth = getattr(packet['wlan_radio'], 'bandwidth', 'Could not be found.')
#             # spatial_strms = getattr(packet['wlan_radio'], 'spatial_strms', 'Could not be found.')
#             channel = getattr(packet['wlan_radio'], 'channel', 'Could not be found.')
#
#             try:
#                 freq = float(packet['wlan_radio'].frequency)
#             except (AttributeError, ValueError):
#                 freq = 0.0
#
#             speed = float(getattr(packet['wlan_radio'], 'data_rate', '0.0'))
#             strength = getattr(packet['wlan_radio'], 'signal_dbm', 'Could not be found.')
#             shortgi = getattr(packet["radiotap"], "flags_shortgi", "Could not be found.")
#
#             band = "2.4 GHz" if freq < 3000 else "5 GHz"
#
#             captures.append({
#                 "BSSID": bssid,
#                 "SSID": ssid,
#                 "Receiver Mac": ra,
#                 "Transmitter Mac": ta,
#                 "Type/Subtype": type_subtype,
#                 "PHY Type": phy,
#                 # "MCS index": mcs_idx,
#                 # "Bandwidth": bandwidth,
#                 # "Spatial streams": spatial_strms,
#                 "Channel": channel,
#                 "Frequency (MHz)": freq,
#                 "Data Rate (Mbps)": speed,
#                 "Signal Strength (dBm)": strength,
#                 "Short GI": shortgi,
#                 "TSF timestamp": tsf,
#                 "Band": band
#             })
#         except AttributeError:
#             continue
#
#     cap.close()
#     return pd.DataFrame(captures)
#
#
#
#
#
# df = pcap_Parser("TUC.pcapng")
# print(df)



def analyze_ap_signal_strength(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='wlan.fc.type_subtype == 0x08')

# to defaultdict ap_data einai gia kathe ena AP.
# To defaultdict leitourgei etsi: An pame na valoume ena key pou DEN einai mesa, tote automata tha dimiourgisoume
# mia nea kataxwrish, pou periexei ena SET ssids, ena LIST rssi_values, kai mia metavlith channel (krataei to channel pou ekpempei to AP)
    ap_data = defaultdict(lambda: {'ssids': set(), 'rssi_values': [], 'channel' : None})

#To channel usage dictionary krataei ws key ena channel kai ws values tis BSSID olwn twn AP pou ekpempoun se auto
# (einai gia na vroume meta posa AP kanoun overlap)
    channel_usage = {}

#edw krataw sto telos ola ta dedomena mazi gia kathe ap : posa ssid ekpempei, average signal strength
    summarized_ap_data = {}

#to dictionary gia to penalty pou tha prosthetei sto congestion score to prwtokollo pou xrhsimopoioume
    phy_weights = {
        '1': 4,  # 802.11a
        '2': 5,  # 802.11b
        '3': 4,  # 802.11g
        '4': 3,  # 802.11n
        '5': 2,  # 802.11ac
        '6': 1  # 802.11ax (Wi-Fi 6)
    }



    for packet in cap:
        try:
            hex_ssids = getattr(packet['wlan.mgt'], 'wlan_ssid', 'Hidden SSID')
            ssid = hex_ssid_to_string(hex_ssids)
            bssid = getattr(packet['wlan'], 'bssid', None)
            rssi = getattr(packet['wlan_radio'], 'signal_dbm', None)
            channel = getattr(packet['wlan_radio'], 'channel', None)
            phy = getattr(packet['wlan_radio'], 'phy', None)

            if bssid and rssi and channel:
                rssi = int(rssi)  # Convert RSSI to integer
                channel = int(channel)

                ap_data[bssid]['ssids'].add(ssid) #add giati to ssids einai SET (to grafw k panw)
                ap_data[bssid]['rssi_values'].append(rssi) #append giati to rssi_values einai DICTIONARY
                ap_data[bssid]['channel'] = channel
                ap_data[bssid]['phy'] = phy

                channel_usage.setdefault(channel, []) #An den uparxei hdh to channel ws key, dhmiourgoume lista gia values kai mpainei to kathe BSSID
                if bssid not in channel_usage[channel]: # elegxos gia na MHN mpei parapanw apo mia fora to BSSID sth lista tou channel
                    channel_usage[channel].append(bssid)
        except AttributeError:
            continue

    cap.close()

    #Calculate and display average signal strength per AP per SSID
    for bssid, data in ap_data.items():
        avg_rssi = sum(data['rssi_values']) / len(data['rssi_values']) if data['rssi_values'] else None
        ssid_list = ', '.join(data['ssids'])
        channel = data['channel']
        overlap_count = len(channel_usage[channel]) if channel else 0
        phy = data['phy']



        #ta varh, den exei kathe tomeas idia shmasia
        if channel <= 13:  # 2.4 GHz band
            # In 2.4 GHz: overlap matters most, RSSI slightly less due to longer range
            w_ssid = 1.5  # Beacons can increase airtime usage in 2.4 GHz
            w_overlap = 4.5  # Severe congestion due to very limited spectrum
            w_rssi = 2.5  # Signal is important, but range compensates a bit
            w_phy = 1.5  # Modern PHY helps, but 2.4 GHz can't use features like OFDMA well
        else:  # 5 GHz band
            # In 5 GHz: RSSI matters more (shorter range), overlap is less impactful
            w_ssid = 1  # Less airtime pressure in wider spectrum
            w_overlap = 0.7  # More available bandwidth, overlap is less damaging
            w_rssi = 5  # Signal strength matters more due to attenuation and short range
            w_phy = 3.3  # Modern PHY (e.g., 802.11ax) performs significantly better in 5 GHz
            avg_rssi += 6 # +6dB compensation for shorter range compared to 2.4GHz

        phy_score = phy_weights[str(phy)]
        density_score = w_ssid*len(data['ssids']) + w_overlap*overlap_count + w_phy*phy_score + w_rssi*abs(avg_rssi/10)


        # add the summary of the AP to the dictionary
        summarized_ap_data[bssid] = {
            'ssid_count': len(data['ssids']),
            'avg_rssi': round(avg_rssi, 2) if avg_rssi is not None else None,
            'overlapping_channels': overlap_count,
            'phy_type': phy,
            'density_score': density_score
        }

        print(f"AP {bssid} broadcasts {len(data['ssids'])} SSIDs: {ssid_list:<17} | Avg RSSI: {avg_rssi:.2f} dBm | Channel: {channel} | Overlapping APs: {overlap_count} | Phy Type: {  phy} | Density : {density_score:.2f}")

    # for key, value in channel_usage.items():
    #     print(f"Channel {key} has APs {value}")
# Run the function with your PCAP file
analyze_ap_signal_strength("TUC.pcapng")