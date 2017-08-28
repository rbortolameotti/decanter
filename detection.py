import editdistance
import glob
from fingerprint import FingerprintManager

class DetectionModule():
    
    def __init__(self):
        self.background_threshold = 2.5
        self.browser_threshold = 2.0
        self.outgoing_threshold = 1000
        self.known_browsers_str = ['Firefox', 'Chrome', 'MSIE', 'Edge', 'Opera', 'Safari'] # TODO
        self.update_threhshold = 0.1 # TODO
        
        
    def detection(self, trained_fingerprints, new_fingerprint):
        """
            Verify if the new fingerprint matches with any of the existing fingerprint of a specific host.
            
            Parameter
            ----------
            host_fingerprints : list of Fingerprint
                List of existing application fingerprints of a specific host
            
            new_fingerprint : Fingerprint
            
            Return
            ----------
            True/False :
                If there are no similar fingerprints and: outgoing is too high, or they contain browser strings,
                then --> return True
                
                --> return False if it is similar to an existing fingerprint or it is a software update.
        """

        if new_fingerprint == None:
            return False
        
        # Check if new_fingerprint is similar to any existing fingerprint.
        for trained_f in trained_fingerprints:
            if self.similarity_check(new_fingerprint, trained_f):
                return False
                
        # Check if the new_fingerprint exfiltrates enough data to be considered as an alert.
        if new_fingerprint.outgoing_info > self.outgoing_threshold:
            if self._is_update(new_fingerprint, trained_fingerprints): # TODO
                return False # TODO
            else:
                return True  # It is not an update --> trigger alert.
        
        # If new_fingerprint tries to be a browser (and it is likely not a browser), then an alert is triggered.
        if self._fake_browser(new_fingerprint.user_agent): # TODO
            return True
        else:
            return False
        
        
    def _is_update(self, alert_fingerprint, trained_fingerprints): # TODO
        """
            This method verifies if the alert is triggered by an updated version of a known software.
            
            Parameters
            ---------------
            alert_fingerprint: Fingerprint
                The alert that is going to be triggered
            
            trained_fingerprints: List of Fingerprint
                The list of known fingerprints for the specific host.
                
            Return
            ---------------
            result : boolean (False/True)
                Returns True if the alert is considered an update of a known fingeprint, False otherwise.
        """
        result = False

        for fingerprint in trained_fingerprints:
            
            if alert_fingerprint.method == fingerprint.method:

                # Compute similarity among User-Agents.
                ua_similarity_distance = self._ua_distance(alert_fingerprint.user_agent[0], fingerprint.user_agent[0])
                
                if ua_similarity_distance <= self.update_threhshold:

                    # Check if the other features between the alert and the fingerprint are matching.
                    if self._similar_alert(alert_fingerprint, fingerprint):
                        print """
                            Update Found:
                            
                            From ---> {}
                            
                            To   ---> {}
                        """.format(fingerprint, alert_fingerprint)
                        result = True
                        fingerprint.user_agent = alert_fingerprint.user_agent
                        return result
        return result
                    
                
    # Compute the similarity between two user-agent strings. The lower the values, the more similar the strings are.
    def _ua_distance(self, new_ua, old_ua): # TODO
        dist = float(editdistance.eval(new_ua, old_ua))
        if len(new_ua) > len(old_ua):
            dist /= len(new_ua)
        else:
            dist /= len(old_ua)
        return dist
    
    
    # Verifiy if the features (other than UA) are still similar between the two fingerprints.
    def _similar_alert(self, alert, fingerprint): # TODO
        similar = False
        if alert.label == fingerprint.label:
            score = 1.0
            if alert.label == "Background":
                score += self._header_check(alert.constant_header_fields, fingerprint.constant_header_fields)
                score += self._avg_size_check(alert.avg_size, fingerprint.avg_size)
                score += self._host_check(alert.hosts, fingerprint.hosts)
                if score >= self.background_threshold:
                    similar = True
                    return similar
            elif alert.label == "Browser":
                score += self._language_check(alert.language, fingerprint.language)
                if score >= self.browser_threshold:
                    similar = True
                    return similar
            else:
                raise AttributeError("The label of the alert is neither Browser nor Background.")
        return similar
    
    
    # Verify if the fingerprint contains string of known browsers. If it does, than it is likely to be a malicious
    # connection trying to communicate with a browser-like user agent. This check is done after the "outgoing threshold
    # check.
    def _fake_browser(self, user_agent_string): # TODO
        for s in self.known_browsers_str:
            if s in user_agent_string[0]:
                return True
        return False
    
    
    def similarity_check(self, new_f1, old_f2):
        """
            Verify if two fingerprints are similar
            
            Parameter
            -----------
            new_f1, old_f2 : Fingerprint

                
            Result:
            -----------
            True : if new_f1 and old_f2 are similar
            False: otherwise
        """
        score = 0.0
        
        # Fingerprints are not similar if they represents two different type of application
        if new_f1.label != old_f2.label:
            return False
        
        # Check if Background-type fingerprints are similar
        if new_f1.label == "Background":
            score = self._background_similarity(new_f1, old_f2)
            if score >= self.background_threshold:
                return True
            else:
                return False
        
        # Check if Browser-type fingerprints are similar
        else:
            score = self._browser_similarity(new_f1, old_f2)
            if score >= self.browser_threshold:
                return True
            else:
                return False
    
    
    # Compute Background-type fingerprint similarity based on their core features.
    def _background_similarity(self, new_f1, old_f2):
        score = 0.0
        score += self._host_check(new_f1.hosts, old_f2.hosts)
        score += self._avg_size_check(new_f1.avg_size, old_f2.avg_size)
        score += self._header_check(new_f1.constant_header_fields, old_f2.constant_header_fields)
        score += self._ua_check(new_f1.user_agent, old_f2.user_agent)
        return score
    
    
    # Compute Browser-type fingerprint similarity based on their core features.
    def _browser_similarity(self, new_f1, old_f2):
        score = 0.0
        score += self._ua_check(new_f1.user_agent, old_f2.user_agent)
        score += self._language_check(new_f1.language, old_f2.language)
        return score
    
    
    # Check if the set of hosts of the old fingerprint is a superset of the new list of hosts.
    def _host_check(self, new_host_list, old_host2_list):
        result = 0.0
        for host,count in new_host_list:
            if host not in [o[0] for o in old_host2_list]:
                return result
        result = 1.0
        return result
    
    
    # Check if the average request size of the new fingerprint falls within a certain range 
    # from the average size of the old fingerpring 
    def _avg_size_check(self, new_avg, old_avg):
        avg_percentage_error = 30
        result = 0.0
        error_margin = (float(old_avg)/ 100) * avg_percentage_error
        
        if (float(old_avg) + error_margin) >= float(new_avg) >= (float(old_avg) - error_margin):
            result = 1.0
            return result
        elif (float(old_avg) + 2 * error_margin) >= float(new_avg) >= (float(old_avg) - 2 * error_margin):
            result = 0.5
            return result
        else:
            return result
        
        
    # Check if the set of constant headers of the new fingerprint fully or partially match with the
    # list of constant headers of the old fingerprint.
    def _header_check(self, new_const_headers, old_const_headers):
        matches = 0
        result = 0.0
        for header in new_const_headers:
            if header in old_const_headers:
                matches += 1
        if matches == len(old_const_headers) and len(new_const_headers) == len(old_const_headers):
            result += 1.0
            return result
        elif matches == len(old_const_headers) and len(new_const_headers) > len(old_const_headers):
            result += 0.5
            return result
        else:
            return result
        
    
    # Check if the two user-agent values match.
    def _ua_check(self, new_ua, old_ua):
        result = 0.0
        if new_ua == old_ua:
            result += 1.0
            return result
        else:
            return result
        
    
    # Check if the two language values match.
    def _language_check(self, new_lang, old_lang):
        result = 0.0
        if new_lang == old_lang:
            result += 1.0
            return result
        else:
            return result


class OfflineDetector:
    def __init__(self, folder_path):
        self.files = glob.glob(folder_path + "*.csv")
        self.files = sorted(self.files, key=lambda tmp: tmp[84:])
        self.training_manager = FingerprintManager()
        self.testing_manager = FingerprintManager()
        self.detector = DetectionModule()
        
        
    def _load_from_csv(self):
        for f in self.files:
            if "training" in f:
                self.training_manager.read_from_file(f)
                print "" + f + " has been loaded for training."
            else:
                self.testing_manager.read_from_file(f)
                print "" + f + " has been loaded for testing."
                
    def _load_from_csv_2(self):
        for f in self.files:
            if "training" in f:
                self.training_manager.read_from_file(f)
                print "" + f + " has been loaded for training."
            #else:
            #    self.testing_manager.read_from_file(f)
            #    print "" + f + " has been loaded for testing."
                
    def run_detection_2(self):
        alerts = []
        benign = []
        self._load_from_csv_2()
        all_training_fingerprints = []
        total_files = 0
        total_detected = 0
        
        for h, fingerprints in self.training_manager.hosts_fingerprints.iteritems():
            for f in fingerprints:
                all_training_fingerprints.append(f)
        
        for f in self.files:
            if "testing" in f:
                self.testing_manager.read_from_file(f)
                for host,test_fingerprints in self.testing_manager.hosts_fingerprints.iteritems():
                    total_files += 1
                    detected = False
                    for fingerprint in test_fingerprints:
                        if self.detector.detection(all_training_fingerprints, fingerprint):
                            if not detected:
                                total_detected += 1
                                detected = True
                            alerts.append(fingerprint)
                        else:
                            benign.append(fingerprint)
                    if not detected:
                        print host
                self.testing_manager.hosts_fingerprints = dict()
        print """{}/{} files detected.""".format(total_detected, total_files)
        return alerts, benign
    
    def run_detection(self):
        alerts = []
        benign = []
        self._load_from_csv()
        all_training_fingerprints = []
        
        total_files    = 0
        total_detected = 0
        for h, fingerprints in self.training_manager.hosts_fingerprints.iteritems():
            for f in fingerprints:
                all_training_fingerprints.append(f)
        for host,test_fingerprints in self.testing_manager.hosts_fingerprints.iteritems():
            total_files += 1
            detected = False
            for fingerprint in test_fingerprints:
                if self.detector.detection(all_training_fingerprints, fingerprint):
                    if not detected:
                        total_detected += 1
                        detected = True
                    alerts.append(fingerprint)
                else:
                    benign.append(fingerprint)
            if not detected:
                print host
        
        print """{}/{} files detected.""".format(total_detected, total_files)
        #print "Benign: " , len(benign)
        #print "Alerts: " , len(alerts)
        #for x in alerts:
        #    print x
            
        # TODO added for testing purposes
        return alerts, benign

