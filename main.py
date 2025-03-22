import sys
import matplotlib.pyplot as plt
import pyshark
import pandas as pd
from collections import defaultdict

#pd.set_option("display.max_rows", None)
#pd.set_option("display.max_columns", None)
#pd.set_option("display.width", 1000)
#pd.set_option("display.colheader_justify", "left")
#pd.set_option("display.expand_frame_repr", False)


'''======================================================PCAP PARSER========================================================================'''

def hex_ssid_to_string(hex_ssid):
    hex_str = hex_ssid.replace(":", "")
    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')


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
                ap_data[bssid]['rssi_values'].append(rssi) #append giati to rssi_values einai lista
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
        avg_rssi = sum(data['rssi_values']) / len(data['rssi_values']) if data['rssi_values'] else None  #meso oro signal strength
        ssid_list = ', '.join(data['ssids'])
        channel = data['channel']
        overlap_count = len(channel_usage[channel]) if channel else 0
        phy = data['phy']

        # ta varh, den exei kathe tomeas idia shmasia
        if channel <= 13:  # 2.4 GHz band
            # In 2.4 GHz: overlap matters most, RSSI slightly less due to longer range
            w_ssid = 1  # Beacons can increase airtime usage in 2.4 GHz
            w_overlap = 1  # Severe congestion due to very limited spectrum
            w_rssi = 1  # Signal is important, but range compensates a bit
            w_phy = 1  # Modern PHY helps, but 2.4 GHz can't use features like OFDMA well
        else:  # 5 GHz band
            # In 5 GHz: RSSI matters more (shorter range), overlap is less impactful
            w_ssid = 0.66  # Less airtime pressure in wider spectrum
            w_overlap = 0.16  # More available bandwidth, overlap is less damaging
            if avg_rssi > -60:
                w_rssi = 0.5  # give bonus (less density points) to 5ghz for good connection
            elif -75 < avg_rssi < -60:
                w_rssi = 1.5  # penalize 5ghz more than 2.4ghz for unstable connection (somewhat bad rssi)
            else:
                w_rssi = 2.0  # penalize 5ghz even more for bad rssi due to strong attenuation
            w_phy = 0.5  # Modern PHY (e.g., 802.11ax) performs significantly better in 5 GHz
            avg_rssi += 6  # +6dB compensation for shorter range compared to 2.4GHz

        phy_score = phy_weights[str(phy)]
        density_score = w_ssid*len(data['ssids']) + w_overlap*overlap_count + w_phy*phy_score + w_rssi*abs(avg_rssi/10)


        # add the summary of the AP to the dictionary
        summarized_ap_data[bssid] = {
            'ssid_count': len(data['ssids']),
            'avg_rssi': round(avg_rssi, 2) if avg_rssi is not None else None,
            'overlapping_channels': overlap_count,
            'phy_type': phy,
            'density_score': density_score,
            'channel': channel
        }

        print(f"AP {bssid} broadcasts {len(data['ssids'])} SSIDs: {ssid_list:<17} "
              f"| Avg RSSI: {avg_rssi:.2f} dBm"
              f"| Channel: {channel}"
              f"| Overlapping APs: {overlap_count} "
              f"| Phy Type: {phy} "
              f"| Density : {density_score:.2f}")

    return summarized_ap_data

'''========================================================================================================================================'''


'''======================================================Visualizer========================================================================'''
def visualizer(data, netname):

    bssids = list(data.keys())
    density_scores = []
    avg_rssis = []
    phy_types = []
    ssid_counts = []
    ovrlpchannel_counts = []

    #kratame ta dedomena apo to dict pou gyrise i panw synartisoula tou georgiou
    # (key -> bssid , values -> ssid count , avg rssi ,  ovrl chan , phy , density score)

    for bssid in bssids:
        density_scores.append(data[bssid]['density_score'])
        avg_rssis.append(data[bssid]['avg_rssi'])
        phy_types.append(str(data[bssid]['phy_type'])) #string giati o counter pio katw tha ta pathei
        ssid_counts.append(data[bssid]['ssid_count'])
        ovrlpchannel_counts.append(data[bssid]['overlapping_channels'])

    #ta sortaroume kai ta pairname se duo nees metablitoules gia na fainontai wraia
    sorted_data = sorted(zip(bssids, density_scores), key=lambda x: x[1], reverse=True)
    sorted_bssids, sorted_density_scores = zip(*sorted_data)

    #======PLOT 1===========

    #auto afora to na doume se grafima poso pykno einai ta aps se morfi barwn

    plt.figure(figsize=(14, 6))
    plt.bar(sorted_bssids, sorted_density_scores, color='b', align='edge', width=0.6)
    plt.title(f"Density Score Of {netname}", fontsize=14, fontweight="bold")
    plt.ylabel("Density Score", fontsize=12)
    plt.xlabel("BSSID",fontsize=12)
    plt.xticks(rotation=45, fontsize=6)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


    #======PLOT 2===========
    #kanoume gia na doume posa aps einai isxyra se syma kai posa astheni
    plt.figure(figsize=(14, 6))
    plt.hist(avg_rssis, bins=100, color='b', alpha=0.6)
    plt.title(f"RSSI Of {netname}", fontsize=14, fontweight="bold")
    plt.ylabel("number of APs", fontsize=12)
    plt.xlabel("Average RSSI (dBm)", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.show()

    #======PLOT 3===========
    #kanoume gia na doume mia banda einai pio pykni (meso oro)

    avg_density_24 = meanDensity(data, "2.4")
    avg_density_5 = meanDensity(data, "5")


    #jekiname to plotarisma
    labels = ["2.4 GHz", "5 GHz"]
    density_scores = [avg_density_24, avg_density_5]
    colors = ['crimson', 'royalblue']
    edge_colors = ['darkred', 'darkblue']

    plt.figure(figsize=(14, 8))
    bars = plt.bar(labels, density_scores, color=colors, edgecolor=edge_colors, width=0.6)
    plt.title(f"Average Density Score: 2.4GHz VS 5GHz ({netname}", fontsize=16, fontweight="bold")
    plt.ylabel("Density Score", fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.gca().set_facecolor('#f9f9f9')

    #bazoume apo panw to sunolo ths kathe bandas
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, f'{height:.1f}',
                 ha='center', fontsize=10, fontweight='bold', color='black')

    plt.tight_layout()
    plt.show()
    

def compare_networks(NetData, NetName):

    #meso density gia to ena wifi
    avg1_24 = meanDensity(NetData[0], "2.4")
    avg1_5 = meanDensity(NetData[0], "5")

    #gia to allo
    avg2_24 = meanDensity(NetData[1], "2.4")
    avg2_5 = meanDensity(NetData[1], "5")

    #synoliko meso density
    total1 = (avg1_24 + avg1_5) / 2
    total2 = (avg2_24 + avg2_5) / 2

    #=====PLOT 1=======
    #sygkrisi pyknotitas metaju toy kathe wifi

    labels = [NetName[0], NetName[1]]
    values = [total1, total2]
    colors = ['teal', 'indigo']

    plt.figure(figsize=(14, 6))
    bars = plt.bar(labels, values, color=colors, width=0.5)
    plt.title("Total Density for each Network", fontsize=14, fontweight="bold")
    plt.ylabel("Total Mean Density", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, f'{height:.1f}', ha='center', fontsize=10, color='black')

    plt.tight_layout()
    plt.show()


    #=====PLOT 2=======
    #sygkrisi pyknotitas  ths kathe bandas gia kathe gouifi

    labels = ['2.4GHz', '5 GHz']
    x = range(len(labels))
    width = 0.35

    plt.figure(figsize=(14, 6))
    plt.bar([i - width / 2 for i in x], [avg1_24, avg1_5], width=width, label=NetName[0], color='orangered')
    plt.bar([i + width / 2 for i in x], [avg2_24, avg2_5], width=width, label=NetName[1], color='dodgerblue')

    plt.title("Density of channels in each Network", fontsize=14, fontweight="bold")
    plt.ylabel("Density of Channels", fontsize=12)
    plt.xticks(x, labels)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

#utility function gia na paroume to meso oro tou desnsity ana banda (dry code opws leei kai o nikolis)
def meanDensity(data, band):
    total = 0
    count = 0

    for bssid in data.keys():
        channel = data[bssid].get("channel")
        if channel is not None:
            if band == "2.4" and channel <= 13:
                total += data[bssid]['density_score']
                count += 1
            elif band == "5" and channel > 13:
                total += data[bssid]['density_score']
                count += 1

    return total / count if count > 0 else 0


'''==========================================================================================================================================='''


def main():

    pcap_file1 = "TUC.pcapng"
    pcap_file2 = "MyHome.pcapng"

    print(f"Reading {pcap_file1}")
    data1 = analyze_ap_signal_strength("TUC.pcapng")

    print(f"Reading {pcap_file2}")
    data2 = analyze_ap_signal_strength("random.pcapng")

    visualizer(data1, "TUC")
    visualizer(data2, "MyHome")

    compare_networks([data1, data2], ["TUC", "MyHome"])


if __name__ == "__main__":
    main()