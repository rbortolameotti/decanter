import editdistance
import glob
from fingerprint import FingerprintManager

class DetectionModule():
    """
    This class is responsible to compare fingerprints and identify potentially malicious requests.
    """
    
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
                    
                
    def _ua_distance(self, new_ua, old_ua): 
        """
        This method  computes the similarity between two user-agent strings. 
        The lower the values, the more similar the strings are.

            Parameters
            ---------------
            new_ua : string
                The new User-Agent we want to compare.

            old_ua : string
                The old User-Agent that is (presumably) changed.

            Returns
            ---------------
            dist : float
                The similarity between new_ua and old_ua.
        """
        dist = float(editdistance.eval(new_ua, old_ua))
        if len(new_ua) > len(old_ua):
            dist /= len(new_ua)
        else:
            dist /= len(old_ua)
        return dist
    
    
    def _similar_alert(self, alert, fingerprint): 
        """
        This methods verifies that the features, other than the User-Agent, are (still) similar between two fingerprints.

        The goal of this method is to verify how much similar is a potential alert to an existing fingerprint.

            Parameters
            --------------
            alert : Fingerprint
                Fingerprint that is considered an alert.
            fingerprint : Fingerprint
                Fingerprint that we want to compare with the alert.

            Returns
            --------------
            similar : boolean
                True if the alert and the fingerprint are indeed similar, False otherwise.
        """
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
    
    
    def _fake_browser(self, user_agent_string): 
        """
        This methods verifies if the fingerprint contains a string of a known browser.
        If it does, than it is likely to be a malicious connection trying to communicate with a browser-like User-Agent.

        This check is performed after the "outgoing treshold" check.

            Parameter
            -------------
            user_agent_string : string
                The User-Agent of a fingerprint that we want to verify

            Returns
            -------------
            True if it matches a known browser fingerprint, False otherwise.
        """
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
    
    
    def _background_similarity(self, new_f1, old_f2):
        """
        This method computes the similarity between two Background-type fingerprints based on their core features.

            Parameters
            --------------
            new_f1 : (Background) Fingerprint
            old_f2 : (Background) Fingerprint

            Returns
            --------------
            score : float
                The similarity score between two Background-type fingerprints
        """
        score = 0.0
        score += self._host_check(new_f1.hosts, old_f2.hosts)
        score += self._avg_size_check(new_f1.avg_size, old_f2.avg_size)
        score += self._header_check(new_f1.constant_header_fields, old_f2.constant_header_fields)
        score += self._ua_check(new_f1.user_agent, old_f2.user_agent)
        return score
    
    
    def _browser_similarity(self, new_f1, old_f2):
        """
        This method computes the similarity between two Browser-type fingerprints based on their core features.

            Parameters
            --------------
            new_f1 : (Browser) Fingerprint
            old_f2 : (Browser) Fingerprint

            Returns
            --------------
            score : float
                The similarity score between two Browser-type fingerprints
        """
        score = 0.0
        score += self._ua_check(new_f1.user_agent, old_f2.user_agent)
        score += self._language_check(new_f1.language, old_f2.language)
        return score
    
    
    def _host_check(self, new_host_list, old_host2_list):
        """
        This method checks if the set of hosts of the old fingerprint is a superset of the new fingerprint's list of hosts.

            Parameters
            --------------
            new_host_list: list of string
            old_host2_list : list of string

            Returns
            -------------
            result : float
                The result of this similarity function between the HTTP host features.
        """
        result = 0.0
        for host,count in new_host_list:
            if host not in [o[0] for o in old_host2_list]:
                return result
        result = 1.0
        return result
    
    
    def _avg_size_check(self, new_avg, old_avg):
        """
        This method checks if the average request size of the new fingerprint falls within a certain range 
        from the average size of the old fingerprint.

            Parameters
            --------------
            new_avg: int
            old_avg: int

            Returns
            --------------
            result : float
                The result of this similaritfy function based on the average size of HTTP requests
        """
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
        
        
    def _header_check(self, new_const_headers, old_const_headers):
        """
        This method checks if the set of constant headers of the new fingerprint fully or partially match with the
        list of constant headers of the old fingerprint.

            Parameters
            ---------------
            new_const_headers: list of string
            old_const_headers: list of string

            Returns
            ---------------
            result: float
                The result of this similarity function based on the constant headers present in HTTP requests.
        """
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
        
    
    def _ua_check(self, new_ua, old_ua):
        """
        This methods verifies that two User-Agents are matching.

            Parameters
            -------------
            new_ua: string
            old_ua: string

            Returns
            -------------
            result: float
                Returns 1.0 if there is a match, 0.0 otherwise.
        """
        result = 0.0
        if new_ua == old_ua:
            result += 1.0
            return result
        else:
            return result
        
    
    def _language_check(self, new_lang, old_lang):
        """
        This methods verifies that two Accept-Language values are matching. (Same check as _ua_check() )

            Parameters
            -------------
            new_lang: string
            old_lang: string

            Returns
            -------------
            result: float
                Returns 1.0 if there is a match, 0.0 otherwise.
        """
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
        

    def _load_from_csv_2(self):
        """
        This method loads fingerprints from a .csv file, but only those flagged for training"
        """
        for f in self.files:
            if "training" in f:
                self.training_manager.read_from_file(f)
                print "" + f + " has been loaded for training."
               

    def run_detection_2(self):
        """
        This method runs the offline detection.

        Fingerprints were previously dumped into csv files. In the offline analysis are loaded
        from the csv files, and then compared.

        Training data is first loaded. The each testing file is analyzed.
        """
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
