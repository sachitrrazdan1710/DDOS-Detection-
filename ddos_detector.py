import joblib
from scapy.all import sniff, IP, TCP, UDP
from plyer import notification
import numpy as np

# Load your new lightweight model
model = joblib.load('light_ddos_model.pkl')

# Feature extraction for 4 features
def extract_features(packet):
    features = []
    
    # Destination Port
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        features.append(packet.dport)
    else:
        features.append(0)
    
    # Total Fwd Packets - simulated as 1 for live packets
    features.append(1)

    # Total Backward Packets - simulated as 1
    features.append(1)
    
    # Flow Duration - simulated by packet time (rough approximation)
    features.append(packet.time)
    
    return features

# Handle each packet
def process_packet(packet):
    try:
        features = extract_features(packet)
        X = np.array(features).reshape(1, -1)
        prediction = model.predict(X)
        if prediction[0] == 1:  # Assuming 1 = DoS attack
            notification.notify(
                title='DDoS Attack Detected!',
                message='Warning! A DDoS attack was detected!',
                timeout=5
            )
            print("🚨 DDoS Attack Detected!")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing
print("Starting real-time DDoS detection...")
sniff(prn=process_packet, store=0)
