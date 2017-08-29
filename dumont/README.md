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
The Dumont API provides functionality for detecting anomalies in network traffic. The API provides this functionality through the `detector` class. The detector handles instances of DumontRequest, provided through `DumontRequest` and `DumontLog` classes. Both of them can be parsed using their respective parse functions `parsePCAP` and `parseLOG`. This section provides documentation for using these classes and functions.

### Parsing
The first stap is to prepare data for the Dumont detector. Depending on the input, the dumont library provides functions to parse this data. There are two possible types of input, .pcap files and .log files. The examples below illustrate the usage of the parse pcap and log parse functions respectively:
```
import dumont

data = dumont.parsePCAP('/path/to/file.pcap')
data = dumont.parseLOG('/path/to/file.log')
```

### Dumont Request
The dumont requests are auxiliary classes which can be used by the detector. They are generated using the parse functions described in the previous subsection. There exist separate classes for being generated through .pcap files and .log files. However, they provide the same functionality through the same API calls. Therefore, this section only discusses the `DumontRequest` class.

#### Attributes
```
# Creating request
request = DumontRequest(<timestamp>, <req>, <ip>)

# Length features
request.l1 # Length of request
request.l2 # Total length of URI
request.l3 # Total length of URI parameters
request.l4 # Total length of headers
request.l5 # Length of request body

# Structural features
request.s1 # Average length of URI parameter names
request.s2 # Average length of URI parameter values
request.s3 # Average length of header names
request.s4 # Average length of header values

# Entropy features
request.e1 # 8-bit entropy of request
request.e2 # 16-bit entropy of request
request.e3 # 24-bit entropy of request
request.e4 # 32-bit entropy of request

# Temporal features
request.t1 # Number of requests in last minute
request.t2 # Number of bytes in last minute
request.t3 # Hour of HTTP request
request.t4 # Week day of HTTP request
```

#### Methods
```
# Creating request
request = DumontRequest(<timestamp>, <req>, <ip>)

# Information about the request if it raises an alert
request.alert() # Alert information of request

# Extract features from request
request.featureVector()  # Return complete feature vector l1-l5, s1-s4, e1-e4, t1-t4
request.featureVectorL() # Return length feature vector l1-l5
request.featureVectorS() # Return structural feature vector s1-s4
request.featureVectorE() # Return entropy feature vector e1-e4
request.featureVectorT() # Return temporal feature vector t1-t4
```

### Detector
The detector is trained using a list of `DumontRequest`s or `DumontLog`s. Once it is trained, it is able to predict whether previously unseen `DumontRequest`s or `DumontLog`s are anomalous comparted to the trained requests. To do so, the detector needs to be trained and fitted with parameters. In this section we describe the process of detection using the Dumont detector.

#### Setting up the detector
Creating the detector requires two parameters, namely:
 * `fp`, the desired false positive rate.
 * `alpha`, the slope of the calibration function.

The `fp` parameter is used in determining the initial width of the SVM kernel upon training. The `alpha` value is used to set the slope of the calibration function, this function determines the optimal width using the ROC curve of the initial SVM's.

```
detector = dumont.detector( fp=0.001,
                            alpha=0.4)
```

#### Training the detector
To train the detector, one first needs to fit it with benign data, i.e. data from regular traffic where no anomalies occured. This stage creates SVM's based on each Dumont feature and feature vector. The second step is to calibrate the SVM's using a combination of regular and anomalous data.

```
detector.fit(benign_data)
detector.fit(benign_calibration_data, malicious_calibration_data)
```

#### Predicting
Once the detector is trained and calibrated, we can use it to predict whether new data is anomalous or regular. For this we feed the detector with a list of previously unseen DumontRequest's and the detector will return a list of booleans for each element in the list. Here False indicates the request on that index is classified as an anomaly and True indicates the request is classified as benign.

```
prediction = detector.predict(unseen_data)
```

### Example Usage
Below we find and example usage where one reads 2 .log files containing data, splits them into fit, calibration and test data and applies this data to the detector which stores alert information in the alerts variable.
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
alerts = [alerts[0].alert() for alerts in zip(malicious_test, prediction) if not alerts[1]]
```

## Tests
TODO

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
