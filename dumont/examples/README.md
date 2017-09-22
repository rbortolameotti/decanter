# Dumont Examples
This directory contains data for testing dumont. The `example.py` script contains example code analogous to the example usage from the parent directory. However, this script uses actual example data from the current directory. Furthermore, it also outputs all alerts on screen instead of storing them into a variable.

## Usage
The `example.py` script can be run by invoking it from the terminal as such `python2 example.py`.

## Data
The `data` directory is split into two subdirectories:
 * `benign` directory contains network traces produced by the VM running for this experiment, without any malware present.
 * `malicious` directory contains network traces produced by the same VM while there was malware running on the system.
The logs in these directories were generated using bro, in the same fashion as DECANTeR. Additionally, the logs have been labeled with an is_malicious label. This way we are able to distinguish between malicious data for training and benign data for training. As the DECANTeR paper describes, labelling was done manually.
