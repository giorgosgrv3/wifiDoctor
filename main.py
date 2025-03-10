import pyshark

cap = pyshark.FileCapture('random.pcapng', display_filter='wlan.fc.type_subtype == 0x08')

def hex_ssid_to_string(hex_ssid):
    # Remove colons and convert hex to bytes
    hex_str = hex_ssid.replace(":", "")
    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')



print(cap[0])

for packet in cap:
    if 'wlan.mgt' in packet:
        print("******* radiotap *******:", packet['radiotap'].field_names)
        print("******* wlan_radio *******:", packet['wlan_radio'].field_names)
        print("***** wlan.mgt *****:", packet['wlan.mgt'].field_names)
        print("******* wlan *******:", packet['wlan'].field_names)
        break  

for packet in cap:
    print(f"Packet layers: {[layer.layer_name for layer in packet.layers]}")
    break  

for pkt in cap:
        
        hex_ssid = getattr(pkt['wlan.mgt'], 'wlan_ssid', 'Could not be found.')
        #hex_ssid = pkt['wlan.mgt'].wlan_ssid XWRIS TO getattr(), apla xrhsimopoioume getattr() gia safety an den uparxei h timh
        ssid = hex_ssid_to_string(hex_ssid)
        print(f"SSID {ssid}")

        #bssid = pkt['wlan'].bssid XWRIS TO getattr(), paromoiws kai gia ta upoloipa
        bssid = getattr(pkt['wlan'], 'bssid', 'Could not be found.')
        print(f"BSSID {bssid}")

        ra = getattr(pkt['wlan'], 'ra', 'Could not be found.')
        print(f"Beacon frame has broadcast MAC {ra}")

        ta = getattr(pkt['wlan'], 'ta', 'Could not be found.')
        print(f"Transmitter MAC Address {ta}")

        channel = getattr(pkt['wlan_radio'], 'channel', 'Could not be found.')
        freq = getattr(pkt['wlan_radio'], 'frequency', 'Could not be found.')
        print(f"Transmits in Channel {channel}, {freq}MHz")

        speed = float(getattr(pkt['wlan_radio'], 'data_rate', 'Could not be found.'))
        print(f"Data rate {speed:.1f} Mb/s")

        strength = getattr(pkt['wlan_radio'], 'signal_dbm', 'Could not be found.')
        strength = pkt['wlan_radio'].signal_dbm
        print(f"Signal strength {strength} dBm")

        

        break
# Print in an aligned format
print(f"{'SSID:':<23}{ssid}")
print(f"{'BSSID:':<23}{bssid}")
print(f"{'Broadcast MAC (ra):':<23}{ra}")
print(f"{'Transmitter MAC (ta):':<23}{ta}")
print(f"{'Channel:':<23}{channel}")
print(f"{'Frequency:':<23}{freq} MHz")
print(f"{'Data Rate:':<23}{speed:.1f} Mb/s")  # Ensures 1 decimal place
print(f"{'Signal Strength:':<23}{strength} dBm")
    
