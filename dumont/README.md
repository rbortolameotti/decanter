# Dumont
This is an implementation of [Dumont](https://doi.org/10.1109/EC2ND.2011.12) in Python 2.7. It is capable of parsing .pcap files or bro .log files (see main repository) and detecting anomalies analogous to the description in the paper.

## Important Notes
Our implementation of Dumont differs from the description in the paper in the following ways:
 1. The kernel width of the One-class SVM is not set by the heuristic in the paper but rather by the scikit-learn One-class SVM default gamma value.
 2. The paper does not describe a method of chosing the steepest line for calibrating the SVM soft margin, so this can be set by the programmer through a value alpha.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. The module can also be used as is for network anomaly detection.

### Prerequisites
Before installing the Dumont package, make sure the following python packages are installed:
 * [brothon](https://github.com/Kitware/BroThon)
 * [dpkt](https://pypi.python.org/pypi/dpkt)
 * [numpy](http://www.numpy.org/)
 * [pandas](http://pandas.pydata.org/)
 * [scipy](https://www.scipy.org/)
 * [scikit-learn](http://scikit-learn.org/stable/)

### Installation
TODO create pip module

## API Reference
TODO

### Example Usage
```
# Import dumont
import dumont

# Read data from log file
benign_data    = dumont.parseLOG('benign.log')
malicious_data = dumont.parseLOG('malicious.log')

# Split data into fit, calibrate and test sets
benign_fit          = benign_data[len(benign_data)/2:]
benign_calibrate    = benign_data[:len(benign_data)/2]
malicious_calibrate = [m for m in malicious_data if m.is_malicious][:100]
malicious_test      = malicious_data

# Create and configure detector
detector = dumont.detector()
detector.fit(benign_fit)
detector.calibrate(benign_calibrate, malicious_calibrate)

# Predict result
prediction = detector.predict(malicious_test)

# Retrieve alerts
alerts = [alerts[0] for alerts in zip(malicious_test, prediction) if not alerts[1]]
```

## Tests
TODO

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
