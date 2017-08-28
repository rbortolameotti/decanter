import pandas as pd
import datetime
from label_generation import LabelGenerator
from fingerprint import Fingerprint, FingerprintGenerator, FingerprintManager 
from detection import DetectionModule

class HTTPRequest():
    """
    This class represents an HTTP request.
    """

    def __init__(self, http_req):
        """
            Initialization of an HTTP Request
            
            Parameter
            ---------------
            http_req : pandas Series
            
        """
        self.uid = http_req.get('uid', None)
        self.ts = http_req.get('ts', None)
        self.orig_ip = http_req.get('id.orig_h', None)
        self.orig_port = http_req.get('id.orig_p', None)
        self.dest_ip = http_req.get('id.resp_h', None)
        self.dest_port = http_req.get('id.resp_p', None)
        self.header_values = http_req.get('header_values', None)
        self.uri = http_req.get('uri', None)
        self.version = http_req.get('version', None)
        self.method = http_req.get('method', None)
        self.orig_mime_type = http_req.get('orig_mime_types', None)
        self.req_body_len = http_req.get('request_body_len', 0)
        
        # TODO : added for evasion analysis
        self.is_malicious = http_req.get('is_malicious', None)
        
        
    def __str__(self):
        return "Request:\n{} {}\nHeaders:\n{}\n".format(self.method, self.uri, self.header_values.items())
    

class Aggregator:
    
    # Timeout used only in testing mode.
    timeout = datetime.timedelta(minutes=10)
    
    # File names for dumping fingerprints in CSV format.
    
    def __init__(self, mode=0, offline=0, dump_testing='testing_fingerprints.csv', dump_training='training_fingerprints.csv'):
        # 0 for Training mode - 1 for Testing mode
        if mode != 0 and mode != 1:
            raise ValueError('The mode value is not valid')
        self.hosts_clusters = {}
        # Thijs - added label generator
        self.label_generator = LabelGenerator()
        self.fin_generator = FingerprintGenerator()
        self.fin_manager = FingerprintManager()
        self.detector = DetectionModule()
        self.mode = mode
        self.alerts = []
        self.time_start = None
        self.time_current = None
        self.offline = offline
        
        # Files for offline dumps
        self.dump_testing  = dump_testing
        self.dump_training = dump_training
        
        # Known browsers
        self.browser_user_agents = set()
        
        # Referrer graphs per user_agent
        self.referrerGraphs = dict()
        
    def change_mode(self, mode):
        if mode != 0 and mode != 1:
            raise ValueError('The mode value is not valid')
        self.mode = mode
        if mode == 1:
            print "Aggregator switched to Testing mode."
        else:
            print "Aggregator switched to Training mode."
    
    def analyze_log(self, data):
        """
            Load and aggregate the HTTP requests from a Dataframe
            
            Parameter
            -------------
            data : pandas Dataframe
        """        
        if (self.mode == 0):
            self._training(data)
        elif (self.mode == 1):
            self._testing(data)
        else:
            pass
        
        
    def _testing(self, data):
        
        for row in data.iterrows():
            
            # Generate HTTP request
            http_data = row[1].to_dict()
            h = HTTPRequest(http_data)
            
            # Initialize Time
            if self.time_start == None:
                self.time_start = h.ts
            
            # Aggregate request
            self._insert_http_request(h)

            # Set current time to the current HTTP request timestamp
            self.time_current = h.ts
            
            # Check if the timeout is expired
            if (self.time_current - self.time_start) > self.timeout:

                # Create and store the fingerprints
                for host in self.hosts_clusters.keys():
                    for app, http_cluster in self.hosts_clusters[host].iteritems():
                        self._create_fingerprints(host, http_cluster)
                
                # Flush the aggregated HTTP requests and reset the starting time
                self.hosts_clusters.clear()
                self.time_start = None
                
        # TODO: we should consider also the case where:
        # - When the log finishes, and the timeout is not triggered, we have to analyze the remaining requests.
        # RESOLVED: added writing of final fingerprints.
        if self.hosts_clusters:
            for host in self.hosts_clusters.keys():
                for app, http_cluster in self.hosts_clusters[host].iteritems():
                    self._create_fingerprints(host, http_cluster)
                    
        self.hosts_clusters.clear()
        self.time_start = None
    
        
    def _training(self, data):
        
        for row in data.iterrows():
            
            # Generate HTTP request
            http_data = row[1].to_dict()
            h = HTTPRequest(http_data)
            
            # Aggregate request
            self._insert_http_request(h)

        # Create and store the fingerprints
        for host in self.hosts_clusters.keys():
            for app, http_cluster in self.hosts_clusters[host].iteritems():
                self._create_fingerprints(host, http_cluster)
        
        # In OFFLINE mode , dump the generated fingerprints in a .csv file.
        if self.offline == 1:
            self.fin_manager.write_to_file(self.dump_training)
        
        self.hosts_clusters.clear()
                
    def _create_fingerprints(self, host, http_cluster):
        """
            Extract GET and POST requests for each Cluster of HTTP requests
            
            Parameter
            ----------------
            http_cluster : list of HTTPRequest
            
            Returns
            ----------------
            (get, post) : tuple (list of HTTPRequests, list of HTTPRequests)
        """
        
        # Removed GET-POST split and replaced with Label_generator
        labels, referrerGraph = self.label_generator.generate_label(http_cluster, self.mode, self.browser_user_agents, self.referrerGraphs)
        
        # Training mode
        if self.mode == 0:
            
            for key, value in labels.items():
                method  = key[0]
                label   = key[1]
                cluster = value
                self.fin_manager.store(host, self.fin_generator.generate_fingerprint(cluster, method, label))
                
                # If browser, store to known browser user-agents
                if label == "Browser":
                    user_agent = http_cluster[0].header_values.get('user-agent', None)
                    self.browser_user_agents.add(user_agent)
            
        # Testing mode
        elif self.mode == 1:
            
            user_agent = http_cluster[0].header_values.get('user-agent', None)
                    
            self.referrerGraphs[user_agent] = referrerGraph
            
            for key, value in labels.items():
                method  = key[0]
                label   = key[1]
                cluster = value
                new_fingerprint = self.fin_generator.generate_fingerprint(cluster, method, label)
            
                # In OFFLINE mode, dump the generated fingerprints in a .csv file. IN THIS CASE WE APPEND!!!!
                if self.offline == 1:
                    self.fin_manager.write_fingerprint_to_file(self.dump_testing, new_fingerprint, host)

                else:
                    host_fingerprints = self.fin_manager.get_host_fingerprints(host)

                    if self.detector.detection(host_fingerprints, new_fingerprint):
                        self.alerts.append(new_fingerprint)
        
        else:
            pass
        
        
    def _insert_http_request(self, req):
        """
            Aggregate the HTTP requests per host and user-agent 
            
            Parameter
            -------------------
            req : HTTPRequest object
        """
        
        # Initialize the clusters for the (previously unseen) host
        if req.orig_ip not in self.hosts_clusters:
            self.hosts_clusters[req.orig_ip] = {}
        
        # Add a request to the cluster of a known host
        if req.orig_ip in self.hosts_clusters:
            
            # Create and/or Update a cluster for those requests that DO NOT HAVE a User-Agent
            if 'user-agent' not in req.header_values:
                if 'None' not in self.hosts_clusters[req.orig_ip]:
                    self.hosts_clusters[req.orig_ip]['None'] = [req]
                else:
                    self.hosts_clusters[req.orig_ip]['None'].append(req)
                    
            # Create and/or Update a cluster for those requests that DO HAVE a User-Agent
            else:
                if req.header_values['user-agent'] not in self.hosts_clusters[req.orig_ip]:
                    self.hosts_clusters[req.orig_ip][req.header_values['user-agent']] = [req]
                else:
                    self.hosts_clusters[req.orig_ip][req.header_values['user-agent']].append(req)


