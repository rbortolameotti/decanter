from brothon import bro_log_reader
import pandas as pd
import networkx as nx
from urlparse import urlparse
import editdistance

class ReferrerGraph:
    """
    Object representing the ReferrerGraph.
    """
    
    def __init__(self, cluster, subdomains=2, time_threshold=600):
        """ Create a Referrer Graph from given filename
            
            Parameters
            ----------
            cluster : array
                Array of HTTPRequest() in the same cluster.
                
            subdomains : int, default = None
                number of specified subdomains to use in checking referrer link
                is set to global self.subdomains when it is not set
                
            time_threshold : int, default = None
                maximum amount of time between requests to use in checking referrer link
                is set to global self.time_threshold when it is not set        
            
            """
        
        """ Store parameters """
        self.subdomains = subdomains
        self.time_threshold = time_threshold
        
        """ Store original filename """
        self.cluster = cluster
        
        """ Store constructed graph """
        self.graph = self._createGraph_(self.cluster)
    
    def write(self, outfile):
        """ Method to write bro graph. 
            
            Parameters
            ----------
            graph : nx.DiGraph()
                graph to be written out.
                
            outfile : string
                name of output file.
                
            """
        mapping = dict()
        
        for node in self.graph.nodes():
            mapping[node] = str(node)
            
        g = nx.relabel_nodes(self.graph, mapping)
        
        nx.write_gml(g, outfile)
        
    def iter_nodes(self):
        """ Method to iterate over all nodes in graph 
            
            Returns
            -------
            result : iterator
                Iterator over nodes of given graph
                
            """      
        
        return self.graph.nodes()
        
    def iter_disconnected_nodes(self):
        """ Method to iterate over disconnected nodes in graph

            Returns
            -------
            result : iterator
                Iterator over disconnected nodes of given graph

            """
        
        undirected_graph = self.graph.to_undirected()

        for node in self.graph.nodes():
            c = 0
            for n in nx.all_neighbors(undirected_graph, node):
                c = 1
                break
            if c != 1:
                yield node

    def iter_connected_nodes(self):
        """ Method to iterate over connected nodes in graph

            Returns
            -------
            result : iterator
                Iterator over connected nodes of given graph

            """
        
        undirected_graph = self.graph.to_undirected()

        for node in self.graph.nodes():
            c = 0
            for n in nx.all_neighbors(undirected_graph, node):
                c = 1
                break
            if c == 1:
                yield node
                
        
    def appendable(self, cluster):
        """ Method to check whether cluster is appendable to current graph.
            
            Parameters
            ----------
            cluster : array
                Array of HTTPRequest() in the same cluster.
                
            Returns
            -------
            connected : array
                Array of HTTPRequest() which could be connected to current graph.
                
            disconnected : array
                Array of HTTPRequest() which could not be connected to current graph.
            
            """
        
        # Create full cluster of original graph and new cluster
        full_cluster = self.cluster
        full_cluster.extend(cluster)
        
        # Create a new ReferrerGraph using full cluster
        appended_graph = ReferrerGraph(full_cluster, self.subdomains, self.time_threshold)
        
        connected    = []
        disconnected = []
        
        # Iterate over connected nodes to see which of the requests
        # in cluster are connected in the newly created graph
        for node in appended_graph.iter_connected_nodes():
            if node in cluster:
                connected.append(node)
               
        # Iterate over disconnected nodes to see which of the requests
        # in cluster are disconnected in the newly created graph
        for node in appended_graph.iter_disconnected_nodes():
            if node in cluster:
                disconnected.append(node)
                
        return connected, disconnected
    
        
    """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """
    """                         Private Methods                         """
    """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """ """
    
    def _createGraph_(self, cluster):
        """ Turn list of HTTPRequests into nx.DiGraph graph
        
            Parameters
            ----------
            cluster : list of HTTPRequests
                list of HTTPRequests objects
                
            Returns
            -------
            result : nx.DiGraph
                Graph object linked using referrer header fields.
                
            """
        
        sorted_cluster = sorted(cluster, key=lambda request: request.ts)
        
        graph = nx.DiGraph()

        headNodes = list()

        for request in sorted_cluster:
            """ Case of head node """
            if self._isHeadNode_(request):
                headNodes.append(request)

            """ General case """
            graph.add_node(request)
            for headNode in reversed(headNodes):
                if self._isLinked_(request, headNode):
                    graph.add_edge(headNode, request)
                    break

        return graph
    
    def _isHeadNode_(self, request, types=['html', 'css', 'javascript', 'flash']):
        """ Method indicating whether a pair is a head node.

            Parameters
            ----------
            request : HTTPRequest
                HTTPRequest queried to be head node
                
            types : array, default = =['html', 'css', 'javascript', 'flash']
                Array of types to accept as headNode

            Returns
            -------
            result : Boolean
                Boolean stating whether request is head node.

            """
        
        for t in types:
            if t in request.header_values.get('accept', ''):
                return True
            
        if '*/*' in request.header_values.get('accept', ''):
            stripped_uri = urlparse(request.uri).path.rsplit('.', 1)
            # If there is an extension
            if len(stripped_uri) == 2:
                for t in types:
                    if t in stripped_uri[1]:
                        return True
            # If there is no extension
            elif len(stripped_uri) == 1:
                return True
            
        return False

    def _isLinked_(self, request, headNode):
        """ Method indicating whether request and headNode are linked.
            
            Parameters
            ----------
            request : HTTPRequest
                HTTPRequest queried to be connected to headNode
            
            headNode : HTTPRequest
                headNode queried to be connected to request
                
            Returns
            -------
            result : Boolean
                Boolean indicating whether request and headNode are connected.
            
            """
        
        # Base _isLinked_ decision on referrer header field,
        # or if this isn't present on the origin header field.
        referrer = request.header_values.get('referer', request.header_values.get('origin', ''))
        host     = headNode.header_values.get('host', '')
        
        # Check whether request and headNode are the same
        if request == headNode:
            return False
        
        # Check if referer is set (ReSurf method)
        elif referrer != '' and host != '':
            referrer = urlparse(referrer).netloc.split('.')[-self.subdomains:]
            host     = urlparse(host).path.split('.')[-self.subdomains:]     
                
            return  referrer == host and abs((request.ts - headNode.ts).total_seconds()) < self.time_threshold
            
        # Check for acceptable favicon.ico request
        elif request.header_values.get('host', None) != None and headNode.header_values.get('host', None) != None:
            # Favicons should be GET requests
            # Favicons should not contain any query containing exfiltrated data
            # Favicons path will request a favicon.ico item
            # Favicons should not have a request body
            isFavicon = request.method == 'GET' and not urlparse(request.uri).query and urlparse(request.uri).path.endswith('ico') and 'favicon' in urlparse(request.uri).path and request.req_body_len == 0
            requestHost  = urlparse(request.header_values.get('host', '')).path.split('.')[-self.subdomains:]
            headHost = urlparse(headNode.header_values.get('host', '')).path.split('.')[-self.subdomains:]
            
            return requestHost == headHost and isFavicon
        # Other cases
        else:
            return False
    
    def _parseHeaderValues_(self, headerValues):
        """ Parse header values from BRO encoding to dictionary.
        
            Parameters
            ----------
            headerValues : string
                header value in bro format
                
            Returns
            -------
            result : dict
                header value in dict format
            
            """
        if headerValues == '-':
            return dict()
        else:       
            return  dict((x, y) for x, y in list(map(lambda entry: (entry.split('||')[0].lower(), entry.split('||')[1].replace('\\x2c', ',')), headerValues.split(','))))
        
        
    def __str__(self):
        connected_nodes    = 0
        disconnected_nodes = 0

        for node in self.iter_connected_nodes():
            connected_nodes += 1

        for node in self.iter_disconnected_nodes():
            disconnected_nodes += 1

        return "ReferrerGraph:\n        Total nodes:       {}\n        Connected nodes:   {}\n        Disconneted nodes: {}".format((connected_nodes + disconnected_nodes), connected_nodes, disconnected_nodes)


class LabelGenerator():
    """
    Object responsible of assigning a label (i.e., Background or Browser) to a fingerprint.
    """
    
    def __init__(self):
        pass
    
    def generate_label(self, cluster, mode=1, browser_user_agents=set(), referrerGraphs=dict()):
        """ Label a cluster as GET or POST and Browser or Background.
            
            Labelling is done on two levels: Browser vs Background and GET vs POST.
            In the end we have four different clusters from the given cluster:
              - Browser    GET  requests
              - Broswer    POST requests
              - Background GET  requests
              - Background POST requests
              
            We create fingerprints for all non-empty requests
            
            Parameters
            ----------
            cluster : list of HTTPRequest
                All HTTP requests belonging to the same application
                
            mode : int, default=0
                0 for training mode, 1 for testing mode.
                
            browser_user_agents : set, default=set()
                Set of known browser user agents, used only in testing mode
                to identify clusters of known browser user agents.
                
            referrerGraphs : dict, default=dict()
                Dictionary of 'user-agent' -> referrerGraph
                Gives a dictionary of the referrerGraphs of all user-agents from the previous timeframe.
                
            Returns
            -------
            result : dict()
                A dict of (method, type) -> list of HTTPRequest
            
            """
        
        # Generate label based on referrer graph
        referrerGraph, label = self._generate_type_label(cluster, mode, browser_user_agents)
        
        # Perform browser checks and split data into browser data and background data
        if label == 'Browser':
            # If training phase
            if mode == 0:
                browser_cluster = cluster
                background_cluster = []
            # If testing phase
            elif mode == 1:
                browser_cluster, background_cluster = self._check_browser_malware(referrerGraph)

        # Suspecter Browser are clusters labelled as Background applications, and have a known "browser" user-agent
        elif label == 'Suspected Browser':

            g = referrerGraphs.get(cluster[0].header_values.get('user-agent', None), None)

            if g is not None:
                connected, disconnected = g.appendable(cluster)
                if len(disconnected) != 0 and len(connected)/len(disconnected) > 0.5:
                    label = 'Browser'
                    browser_cluster, background_cluster = self._check_browser_malware(ReferrerGraph(cluster))
                else:
                    label = 'Background'
                    browser_cluster = []
                    background_cluster = cluster

            else:
                label = 'Background'
                browser_cluster = []
                background_cluster = cluster
            
        elif label == 'Background':
            browser_cluster    = []
            background_cluster = cluster
        else:
            raise ValueError('Encountered unknown label: ', str(label))
            
        
        # Split each cluster according to its method
        browser_get,    browser_post    = self._method_split(browser_cluster)
        background_get, background_post = self._method_split(background_cluster)
        
        result = dict()
        if len(browser_get):
            result[('GET',  'Browser')]    = browser_get
        if len(browser_post):
            result[('POST', 'Browser')]    = browser_post
        if len(background_get):
            result[('GET',  'Background')] = background_get
        if len(background_post):
            result[('POST', 'Background')] = background_post
            
        return result, referrerGraph
    
    
    def _generate_type_label(self, cluster, mode, browser_user_agents, threshold=0.5):
        """ Labels cluster as Browser or Background according to its referrer graph.
        
            All nodes in the cluster are linked based on their referrer value.
            Largely disconnected graphs are labelled Background.
            Largely connected graphs are labbeled Browser.
            
            Parameters
            ----------
            cluster : list of HTTPRequest
                All HTTP requests belonging to the same application
                
            mode : int
                current mode 0 = training, 1 = testing.
                
            browser_user_agents : set
                set of known browser user agents, only used in testing mode.
                
            threshold : float, default=0.5
                Threshold for ratio of nodes that should be linked versus unlinked nodes.
                
            Returns
            -------
            referrerGraph : ReferrerGraph()
                referrerGraph of given cluster
            
            label : string
                Label of cluster
            
            """
        referrerGraph = ReferrerGraph(cluster)
        
        connected_count    = 0
        disconnected_count = 0

        for node in referrerGraph.iter_connected_nodes():
            connected_count    += 1
        for node in referrerGraph.iter_disconnected_nodes():
            disconnected_count += 1

        label = "Background" if float(connected_count) / (connected_count+disconnected_count) < threshold else "Browser"
        
        if label == "Background" and cluster[0].header_values.get('user-agent', None) in browser_user_agents:
            label = "Suspected Browser"

        return referrerGraph, label
    
    
    def _check_browser_malware(self, referrerGraph):
        """ Checks disconnected referrerGraph nodes for data exfiltration attempts.
            
            Iterates over all disconnected nodes in referrerGraph and searches for
            data exfiltration attempts. These are either GET requests with parameters or
            POST requests. If multiple similar requests are sent out, it indicates
            a malicious exfiltration application. Header exfiltration is filtered out
            through a header exfiltration check.
            
            Parameters
            ----------
            referrerGraph : ReferrerGraph()
                referrerGraph of a cluster
                
            Returns
            -------
            browser_requests : list of HTTPRequest
                List of HTTPRequest which are correct browser traffic.
                
            exfiltration_requests : list of HTTPRequest
                List of HTTPRequest which are non-browser data exfiltration attempts.                
            
            """ 
        
        # Create lists of requests to return
        browser_requests      = []
        exfiltration_requests = []
        
        # Fill browser_requests list with all connected nodes
        for node in referrerGraph.iter_connected_nodes():
            browser_requests.append(node)
            
        # Find the exfiltration attempts
        exfiltration_attempts = self._exfiltration_filter(referrerGraph)
        # Find the similarity requests
        similarity_attempts   = self._similarity_filter(referrerGraph)
        # Find header exfiltration attempts
        #header_attempts       = set(self._header_filter(referrerGraph, connections))
        
        # Malicious attempts are the repetitive exfiltration attempts which
        # Exfiltrate more data than a given threshold.
        malicious_attempts = self._exfiltration_similarity_threshold(exfiltration_attempts, similarity_attempts)
        
        """ TODO add header exfiltration filter. """
        
        # If one of the disconnected nodes is a malicious attempt,
        # add it to the exfiltration_requests, otherwise it is benign
        # and can be added to the browser_requets.
        for request in referrerGraph.iter_disconnected_nodes():
            if request in malicious_attempts:
                exfiltration_requests.append(request)
            else:
                browser_requests.append(request)
        
        return browser_requests, exfiltration_requests
    
    
    def _exfiltration_filter(self, referrerGraph):
        """ Check whether naive exfiltration is occuring.
        
            Naive exfiltration occurs with a POST request with data upload 
            or a GET request where parameters are set.
            
            Parameters
            ----------
            referrerGraph : ReferrerGraph()
                referrerGraph of a cluster
                
            Returns
            -------
            exfiltration_attempts : list of HTTPRequest
                List of HTTPRequest where exfiltration attempts occur.
                Only executed over disconnected nodes.
            
            """
        exfiltration_attempts = []
        
        for request in referrerGraph.iter_disconnected_nodes():
            if  request.method == 'POST' and request.req_body_len > 0 or request.method == 'GET'  and urlparse(request.uri).query:
                    exfiltration_attempts.append(request)
                    
        return exfiltration_attempts
                
            
    def _similarity_filter(self, referrerGraph, threshold=0.1):
        """ Check whether requests using the same method to the same URI
            are similar in header values. 
            
            Parameters
            ----------
            connections : dict()
                Dictionary of (request.method, request.uri) -> dict(request)
                
            threshold : float, default=0.1
                To be marked benign, the average Levensteihn distance should be larger than the given threshold.
                Threshold currently states that between every 10 messages at most 1 header field could differ.
                
            Returns
            -------
            result : list of HTTPRequest
                All HTTPRequest of connections for which the similarity filter detected similar requests.
                
            """
        
        # Result storing all requests for which the similarity filter raises an alert
        result = []
            
        # Create a similarity filter for all nodes
        connections = dict();
        for request in referrerGraph.iter_disconnected_nodes():
            key = (request.method, urlparse(request.uri).path)
            connections.setdefault(key, []).append(request)
        
        # Iterate over all connections
        for key, value in connections.items():
            
            total = 0
            # Gather a list of header value tuples (field, value) for all request in the same connection.
            val = map(lambda l: [tup for tup in sorted(l.header_values.items()) if tup[0] != 'content-length'], value)
            
            # Check whether there is more than 1 request per connection
            if len(val) > 1:
                # Compute changes in header values
                for idx in range(len(val)-1):
                    total += editdistance.eval(val[idx], val[idx+1])

                # If average change in header values is too small, raise an alert
                if float(total)/(len(val)-1) <= threshold:
                    for request in value:
                        result.append(request)
                        
        return result
    
    
    def _exfiltration_similarity_threshold(self, exfiltration, similarity, threshold=500):
        """ Check whether the automated data exfiltration attempts exceed a threshold.
            
            To filter false positives we check whether repeating exfiltration
            attempts actually exfiltrate data.
            
            Parameters
            ----------
            exfiltration : list of HTTPRequest
                List of HTTPRequest which have been marked as exfiltrating data.
                
            similarity : list of HTTPRequest
                List of HTTPRequest which have been marked as similar.
                
            threshold : int, default=500
                Threshold for number of bytes which similar requests can exfiltrate.
                
            """
        result = []
        connections = dict()
        
        for request in exfiltration:
            if request in similarity:
                result.append(request)
                
        for request in result:
            key = (request.method, urlparse(request.uri).path)
            connections.setdefault(key, []).append(request)
            
        result = []
            
        for key, value in connections.items():
            parameters = [urlparse(v.uri).query for v in value]
            
            outgoing_information = len(parameters[0])
            
            for idx in range(len(parameters)-1):
                outgoing_information += editdistance.eval(parameters[idx], parameters[idx+1])
                
            if outgoing_information == 0 or outgoing_information > threshold:
                for v in value:
                    result.append(v)
            
        return result
    
    
    def _header_filter(self, referrerGraph, connections, threshold=500):
        """ Check whether data is being exfiltrated through a header field.
            
            Perform check on all disconnected nodes of the graph and check
            whether similar requests contain similar header fields but different
            header values. As request headers stay fairly consistent this could
            indicate data exfiltration.
            
            Parameters
            ----------
            referrerGraph : ReferrerGraph()
                referrerGraph of a cluster
                
            connections : dict()
                Dictionary of (request.method, request.uri) -> dict(request)
                
            threshold : int, default=500
                Threshold of bytes which may be 'exfiltrated' before raising an alert.
                Note that headers such as cookie will differ between requests, this 
                threshold aims to reduce false positives caused by such fields.
            
            Returns
            -------
            result : list of HTTPRequest
                All HTTPRequest of connections for which the similarity filter detected header exfiltration.                
            
            """
        
        tmp    = []
        result = []
        
        for key, value in connections.items():
            
            # First extract headers from all requests
            # Then sort these (field, value) tuples based on field
            # Finally transform list of (field, value) to [list of fields, list of values]
            headers   = map(lambda req: req.header_values.items(), sorted(value, key=lambda v: v.ts))
            s_headers = map(lambda req: sorted(req, key=lambda tup: tup[0]), headers)
            val       = map(lambda req: [list(elem) for elem in zip(*req)], s_headers)
            
            if len(val) > 1:
                total_ld_field = 0
                total_ld_value = 0
                total_ld_indiv = 0
                
                for idx in range(len(val)-1):
                    total_ld_field += editdistance.eval(val[idx][0], val[idx+1][0])                        
                    total_ld_value += editdistance.eval(val[idx][1], val[idx+1][1])
                    
                    for hv in range(min(len(val[idx][1]), len(val[idx+1][1]))):
                        total_ld_indiv += editdistance.eval(val[idx][1][hv], val[idx+1][1][hv])

                avg_ld_field = float(total_ld_field) / (len(val)-1)
                avg_ld_value = float(total_ld_value) / (len(val)-1)
                avg_ld_indiv = float(total_ld_indiv) / (total_ld_value) if total_ld_value != 0 else 0
                
                if  avg_ld_field <= 0.2 and                    total_ld_indiv >= threshold:
                    for request in value:
                        tmp.append(request)
                        
        for node in referrerGraph.iter_disconnected_nodes():
            if node in tmp:
                result.append(node)
                
        return result
                
                        
    
    def _method_split(self, cluster):
        """ Split the cluster in GET and POST requests.
            
            Check for each HTTPRequest in cluster whether it is a GET
            or POST request. Return a list of GET and POST requests based
            on this.
            
            Parameters
            ----------
            cluster : list of HTTPRequest
                List of HTTPRequest which has to be split into GET and POST requests.
                
            Returns
            -------
            get : list of HTTPRequest
                List of HTTPRequest which have method set to GET.
                
            post : list of HTTPRequest
                List of HTTPRequest which have method set to POST.
                
            """
        
        get  = [request for request in cluster if request.method == 'GET']
        post = [request for request in cluster if request.method == 'POST']
        
        return get, post


