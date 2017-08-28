from bro_parser import BroParser
from decanter_new import Aggregator
from evaluation_utils import EvaluationUtils
from detection import OfflineDetector
import sys

def main(argv):
    bp = BroParser()
    training = bp.parseFile('/home/riccardo/Decanter/Project/users/tim/decanter_training_14-11-2016.log')
    testing = bp.parseFile('/home/riccardo/Decanter/Project/users/tim/decanter_testing_15-11-2016.log')    
    decanter_trainer = Aggregator(0,1)

    # Fingerprint training based on 'decanter_training.log'
    #s = datetime.datetime.now()
    #decanter_trainer.analyze_log(training)
    #e = datetime.datetime.now()
    #print "Training time:"
    #print e - s

    # Switch mode - From training to testing.
    #decanter_trainer.change_mode(1)

    # Fingerprint testing based on 'decanter_testing.log'
    #s = datetime.datetime.now()
    #decanter_trainer.analyze_log(testing)
    #e = datetime.datetime.now()
    #print "Testing time:"
    #print e - s

    path = '/home/riccardo/Decanter/Project/users/riccardo/linux/main_eval_10min/'
    o = OfflineDetector(path)
    alerts, benign = o.run_detection_2()
    e = EvaluationUtils(alerts, benign)
    e.output_requests()
    e.detection_performance_2()
    for f in e.unique_fing:
        print f

if __name__ == "__main__":
    main(sys.argv)


