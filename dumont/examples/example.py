# Add sys.path variable such that we are able to import from parent directory
import os
parentdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.sys.path.insert(0,parentdir) 

# Import dumont
import dumont

# Read data from log files
# Merge all benign data files into single benign_data array
benign_data    = dumont.parseLOG('./data/benign/VM_ransomware1.log')
benign_data.extend(dumont.parseLOG('./data/benign/VM_ransomware1.log'))
benign_data.extend(dumont.parseLOG('./data/benign/VM_ransomware1.log'))

# Merge all malicious data files into single malicious_data array
malicious_data = dumont.parseLOG('./data/malicious/malicious_1.log')

# Split data into fit, calibrate and test sets
benign_fit          = benign_data[len(benign_data)/2:]
benign_calibrate    = benign_data[:len(benign_data)/2]
malicious_calibrate = [m for m in malicious_data if m.is_malicious][:20]
malicious_test      = malicious_data

# Create and configure detector
detector = dumont.detector(fp=0.001, alpha=0.2)
detector.fit(benign_fit)
detector.calibrate(benign_calibrate, malicious_calibrate)

# Predict result
prediction = detector.predict(malicious_test)

# Retrieve alerts
alerts = [alerts[0].alert() for alerts in zip(malicious_test, prediction) if not alerts[1]]

# Show alerts
for a in alerts:
    print a, '\n'
