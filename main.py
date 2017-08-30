from bro_parser import BroParser
from decanter_new import Aggregator
from evaluation_utils import EvaluationUtils
from detection import OfflineDetector
import sys
import argparse


def dumped_fingerprint_analysis(path):
    o = OfflineDetector(path)

    # Run detection on the loaded CSV files in path.
    # Files with filename having the string "training" are used for training.
    # Those with "testing" are used for testing.
    alerts, benign = o.run_detection_2()

    # Run the classification performance evaluation.
    e = EvaluationUtils(alerts, benign)
    e.output_requests()
    e.detection_performance_2()

    # Print the unique Fingerprints (i.e., with retraining).
    print """
    Unique Fingerprints: {}
    """.format(len(e.unique_fing))
    for f in e.unique_fing:
        print f


def log_fingerprint_analysis(training_log, testing_log, offline):
    bp = BroParser()
    training = bp.parseFile(training_log)
    testing = bp.parseFile(testing_log)
    
    # Initialize the aggregator.
    # Use Training mode first (i.e., 0)
    # Use offline value passed from the user for offline or online analysis.
    decanter_trainer = Aggregator(0, offline)
    
    # Fingerprint training based on training_log
    decanter_trainer.analyze_log(training)

    # Aggregator switches mode from training to testing (0 --> 1).
    decanter_trainer.change_mode(1)

    # Extract Fingerprints from testing_log
    # If online (i.e., 0), Fingerprints are tested against trained Fingerprints
    # If offline (i.e., 1), testing and training fingerprints are dumped in seperate csv files.
    decanter_trainer.analyze_log(testing)
    
    e = EvaluationUtils(decanter_trainer.alerts, [])
    e._unique_fingerprints()
    
    print """
    Unique Alerts: {}
    """.format(len(e.unique_fing))
    for f in e.unique_fing:
        print f


def main(argv):
    parser = argparse.ArgumentParser(description="DECANTeR: DETection of Anomalous outbouNd HTTP Traffic by Passive Application Fingerprinting")
    parser.add_argument('--csv', type=str, help='Run the evaluation loading Fingerprints from csv files stored in the selected folder. CSV files containing "training" in the filename will be used to train the fingerprints. CSV files having "testing" in the filename will be used for testing.') 
    parser.add_argument('-t', '--training', type=str, help='Bro log file used to train fingerprints.')
    parser.add_argument('-T', '--testing', type=str, help='Bro log file used for testing against trained fingerprints.')
    parser.add_argument('-o', '--offline', type=int, default=1, help='Choose 1 if you want to dump the fingerprints extracted from the logs to .csv files. Choose 0 if you want to run the evaluation from the logs. (default=1).') 


    args = parser.parse_args()
    if args.csv != None:
        dumped_fingerprint_analysis(args.csv)

    if args.training != None and args.testing != None and (args.offline != None):
        log_fingerprint_analysis(args.training, args.testing, args.offline)
    

if __name__ == "__main__":
    main(sys.argv)


