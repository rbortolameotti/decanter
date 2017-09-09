# DECANTeR
This is an implementation of DECANTeR in Python 2.7. It is capable of parsing .log files (generated with Bro and the ad-hoc .bro script in the repository). The tool runs anomaly detection based on a passive fingerprinting technique. More technical details can be found in the paper.

## Important Notes
Our implementation does not sniff the live traffic from the network. It can only analyze data if provided in a Bro .log format.


## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
Before installing the DECANTeR package, make sure the following pyhton packages are installed:
 * [brothon](https://github.com/Kitware/BroThon)
 * [pandas](http://pandas.pydata.org/)
 * [editdistance](https://pypi.python.org/pypi/editdistance)
 * [IPy](https://pypi.python.org/pypi/IPy/)
 * [networkx](https://pypi.python.org/pypi/networkx/)

```
pip install --user brothon pandas editdistance IPy networkx
```

To use our implementation of DECANTeR, you need to transform the .pcap files in bro .log files. Therefore, you need to install [bro](https://www.bro.org/download/packages.html) with its [dependencies](https://www.bro.org/sphinx/install/install.html).

### Generating Bro log files
Run the following command to generate a bro .log file that is parsable by our implementation of DECANTeR.

```
bro -r example.pcap decanter_dump_input.bro
```
The output file called "decanter.log", is the log file parsable by our implementation.
If you have installed bro by compiling it yourself, you will probably have to change the path of the first two lines of the script accordingly to your installation path.

### DECANTeR Functionalities
At the current stage, our implementation provides two type of analysis:
1. Live analysis: you can provide a training and testing log file, and DECANTeR will analyze the data and print the alerts (if any).
2. Offline analysis: you can provide a path folder containing a set of .csv files containing the fingerprints (previously dumped by DECANTeR, see below). DECANTeR will use for training all .csv files that have "training" in their filename, and it will use for testing all .csv files having "testing" in their filename.
3. Dump fingerprints from .log files to .csv: you can provide one file for training and one file for testing, and DECANTeR will generate the fingerprints and dump them to .csv files. This is an intermediary step to run the offline analysis.

### Usage Examples
Examples on how to use DECANTeR to run Live and Offline Analyses, using the test data.

Example of Live analysis:
```
python2 main.py --training test-data/user/log/riccardo_linux_training_16-01.log --testing test-data/user/log/riccardo_linux_testing_18-01.log -o 0

python2 main.py --training test-data/malware/vm7_decanter.log --testing test-data/malware/exiltration_logs/URSNIF_386.pcap.decanter.log -o 0
``` 

Example of Offline analysis:
```
main.py --csv test-data/user/csv/
```

Example of dumping CSV files and running offline analysis:
1. Dump fingerprints in csv files.
```
python2 main.py --training test-data/user/log/riccardo_linux_training_16-01.log --testing test-data/user/log/riccardo_linux_testing_18-01.log -o 1
```

2. Analyze the fingerprints.
```
python2 main.py --csv ./
```

## API Reference
TODO
