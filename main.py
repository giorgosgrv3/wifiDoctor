import pyshark
import pandas as pd

pd.set_option("display.max_rows", None)
pd.set_option("display.max_columns", None)
pd.set_option("display.width", 1000)
pd.set_option("display.colheader_justify", "left")
pd.set_option("display.expand_frame_repr", False)


'''======================================================PCAP PARSER========================================================================'''

def hex_ssid_to_string(hex_ssid):
    hex_str = hex_ssid.replace(":", "")
    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')

def pcap_Parser(file):

    captures = []
    cap = pyshark.FileCapture(file, display_filter='wlan.fc.type_subtype == 0x08')

    for packet in cap:
        try:

            if 'wlan.mgt' in packet:
                hex_ssid = getattr(packet['wlan.mgt'], 'wlan_ssid', 'Could not be found.')
                ssid = hex_ssid_to_string(hex_ssid)
                tsf = getattr(packet['wlan.mgt'], 'fixed_timestamp', 'Not available')
            else:
                ssid = 'Not available'
                tsf = 'Not available'

            bssid = getattr(packet['wlan'], 'bssid', 'Could not be found.')
            ra = getattr(packet['wlan'], 'ra', 'Could not be found.')
            ta = getattr(packet['wlan'], 'ta', 'Could not be found.')
            type_subtype = getattr(packet['wlan'], 'fc_type_subtype', 'Could not be found.')
            phy = getattr(packet['wlan_radio'], 'phy', 'Could not be found.')
            mcs_idx = getattr(packet['wlan_radio'], 'mcs_idx', 'Could not be found.')
            bandwidth = getattr(packet['wlan_radio'], 'bandwidth', 'Could not be found.')
            spatial_strms = getattr(packet['wlan_radio'], 'spatial_strms', 'Could not be found.')
            channel = getattr(packet['wlan_radio'], 'channel', 'Could not be found.')

            try:
                freq = float(packet['wlan_radio'].frequency)
            except (AttributeError, ValueError):
                freq = 0.0

            speed = float(getattr(packet['wlan_radio'], 'data_rate', '0.0'))
            strength = getattr(packet['wlan_radio'], 'signal_dbm', 'Could not be found.')
            shortgi = getattr(packet["radiotap"], "flags_shortgi", "Could not be found.")

            band = "2.4 GHz" if freq < 3000 else "5 GHz"

            captures.append({
                "BSSID": bssid,
                "SSID": ssid,
                "Receiver Mac": ra,
                "Transmitter Mac": ta,
                "Type/Subtype": type_subtype,
                "PHY Type": phy,
                "MCS index": mcs_idx,
                "Bandwidth": bandwidth,
                "Spatial streams": spatial_strms,
                "Channel": channel,
                "Frequency (MHz)": freq,
                "Data Rate (Mbps)": speed,
                "Signal Strength (dBm)": strength,
                "Short GI": shortgi,
                "TSF timestamp": tsf,
                "Band": band
            })
        except AttributeError:
            continue

    cap.close()
    return pd.DataFrame(captures)

'''======================================================================================================================================'''



df = pcap_Parser("TUC.pcapng")
print(df)