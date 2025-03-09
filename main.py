import pyshark

cap = pyshark.FileCapture("random.pcapng")

print(cap[0])
        
