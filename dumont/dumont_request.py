#!/usr/bin/env python
# -*- coding: utf-8 -*-

from   collections import Counter
from   scipy.stats import entropy
from   socket      import inet_ntoa
import datetime
import urlparse

class DumontRequest:
    
    def __init__(self, timestamp, req, ip=None):
        """ A DumontRequest instance requires a timestamp
            and the HTTP request it calculates the length
            (l1-l5), structural (s1-s4), entropy (e1-e4),
            and temporal features (t1-t4) accordingly. 
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
                
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        self.timestamp = timestamp
        self.req = req
        self.ip = ip
        
        # Set length features of request
        self.l1 = self.__l1__(self.req)
        self.l2 = self.__l2__(self.req)
        self.l3 = self.__l3__(self.req)
        self.l4 = self.__l4__(self.req)
        self.l5 = self.__l5__(self.req)
        
        # Set structural features of request
        self.s1 = self.__s1__(self.req)
        self.s2 = self.__s2__(self.req)
        self.s3 = self.__s3__(self.req)
        self.s4 = self.__s4__(self.req)
        
        # Set entropy features of request
        self.e1 = self.__e1__(self.req)
        self.e2 = self.__e2__(self.req)
        self.e3 = self.__e3__(self.req)
        self.e4 = self.__e4__(self.req)
        
        # Set temporal features of request
        self.t1 = self.__t1__(self.timestamp)
        self.t2 = self.__t2__(self.req)
        self.t3 = self.__t3__(self.timestamp)
        self.t4 = self.__t4__(self.timestamp)
    
    def featureVector(self):
        """ Return complete feature vector l1-l5, s1-s4, e1-e4, t1-t4 """
        return [self.l1, self.l2, self.l3, self.l4, self.l5,\
                self.s1, self.s2, self.s3, self.s4,\
                self.e1, self.e2, self.e3, self.e4,\
                self.t1, self.t2, self.t3, self.t4]
    
    def featureVectorL(self):
        """ Return length feature vector l1-l5 """
        return [self.l1, self.l2, self.l3, self.l4, self.l5]
    
    def featureVectorS(self):
        """ Return structural feature vector s1-s4 """
        return [self.s1, self.s2, self.s3, self.s4]
    
    def featureVectorE(self):
        """ Return entropy feature vector e1-e4 """
        return [self.e1, self.e2, self.e3, self.e4]
    
    def featureVectorT(self):
        """ Return temporal feature vector t1-t4 """
        return [self.t1, self.t2, self.t3, self.t4]
    
    """ Extract length features of HTTP requests """
    def __l1__(self, req):
        """ Extracts length of request
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        try:
            return len(req)
        except UnicodeEncodeError:
            return len(req.pack_hdr()) + len(req.body) + 2

    def __l2__(self, req):
        """ Extract total length of URI 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        return len(req.uri)

    def __l3__(self, req):
        """ Total length of URI parameters 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        parsed = urlparse.urlparse(req.uri)
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += len(key)
            length += sum([len(v) for v in value])
        return length

    def __l4__(self, req):
        """ Total length of headers 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        return len(str(req.headers))
    
    def __l5__(self, req):
        """ Length of request body 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        return len(req.body)

    """ Extract structural features of HTTP requests """
    
    def __s1__(self, req):
        """ Extract average length of URI parameter names
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        parsed = urlparse.urlparse(req.uri)
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += len(key)
        return float(length)/len(queryDict) if length != 0 else 0

    def __s2__(self, req):
        """ Average length of URI parameter values
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        parsed = urlparse.urlparse(req.uri)
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += sum([len(v) for v in value])
        return float(length)/len(queryDict) if length != 0 else 0

    def __s3__(self, req):
        """ Average length of header names
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        length = 0
        for key, value in req.headers.items():
            length += len(key)
        return float(length)/len(req.headers) if length != 0 else 0

    def __s4__(self, req):
        """ Average length of header values 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        length = 0
        for key, value in req.headers.items():
            length += len(value)
        return float(length)/len(req.headers) if length != 0 else 0

    """ Extract entropy features of HTTP requests """
    
    def __entropyFromList__(self, l):
        """ Auxiliary method to compute entropy from list 
            
            Parameters
            ----------
            l : list of bytes
                list used to compute the entropy.
            """
        # Calculate number of occurances of each byte
        occurences = Counter(l).items()
        # Calculate probabilities of each occurence
        pk = map(lambda tup: float(tup[1])/len(l), occurences)
        # Compute entropy from probabilities
        return entropy(pk)

    def __e1__(self, req):
        """ 8-bit entropy of request 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        # Transform request into byte array
        try:
            reqBytes = [ord(c) for c in str(req)]
        except UnicodeEncodeError:
            reqBytes = [ord(c) for c in req.pack_hdr() + u'\r\n']
            reqBytes.extend([ord(c) for c in req.body])
            
        # Compute entropy from bytes
        return self.__entropyFromList__(reqBytes)

    def __e2__(self, req):
        """ 16-bit entropy of request 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        # Transform request into byte array
        try:
            reqBytes = [ord(c) for c in str(req)]
        except UnicodeEncodeError:
            reqBytes = [ord(c) for c in req.pack_hdr() + u'\r\n']
            reqBytes.extend([ord(c) for c in req.body])
        # Combine two bites into 16 bit number
        entr16 = [reqBytes[i]<<8 + reqBytes[i+1] for i in range(0, len(reqBytes)-1, 2)]
        # Compute entropy from bytes
        return self.__entropyFromList__(entr16)

    def __e3__(self, req):
        """ 24-bit entropy of request 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        # Transform request into byte array
        try:
            reqBytes = [ord(c) for c in str(req)]
        except UnicodeEncodeError:
            reqBytes = [ord(c) for c in req.pack_hdr() + u'\r\n']
            reqBytes.extend([ord(c) for c in req.body])
        # Combine two bites into 16 bit number
        entr24 = [reqBytes[i]<<16 + reqBytes[i+1]<<8 + reqBytes[i+2] for i in range(0, len(reqBytes)-2, 3)]
        # Compute entropy from bytes
        return self.__entropyFromList__(entr24)

    def __e4__(self, req):
        """ 32-bit entropy of request 
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
            
            """
        # Transform request into byte array
        try:
            reqBytes = [ord(c) for c in str(req)]
        except UnicodeEncodeError:
            reqBytes = [ord(c) for c in req.pack_hdr() + u'\r\n']
            reqBytes.extend([ord(c) for c in req.body])
        # Combine two bites into 16 bit number
        entr32 = [reqBytes[i]<<24 + reqBytes[i+1]<<16 + reqBytes[i+2]<<8 + reqBytes[i+3] for i in range(0, len(reqBytes)-3, 4)]
        # Compute entropy from bytes
        return self.__entropyFromList__(entr32)

    """ Extract temporal features of HTTP requests """
    
    def __t1__(self, timestamp):
        """ Number of requests in last minute 
            
            Note this method differs from the paper, since
            only a single packet is processed at the time
            features within a timeframe whould be acumulated,
            hence we calculate the timestamp instead of t1
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
                
            """
        # Return date object
        return datetime.datetime.utcfromtimestamp(timestamp)

    def __t2__(self, req):
        """ Number of bytes in last minute 
            
            Note this method differs from the paper, since
            only a single packet is processed at the time
            features within a timeframe whould be acumulated,
            hence we calculate the number of bytes instead of t2
            
            Parameters
            ----------
            req : dpkt.http.Request()
                dpkt request retrieved from .pcap file.
                
            """
        return self.__l1__(req)

    def __t3__(self, timestamp):
        """ Hour of HTTP request 
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
                
            """
        return datetime.datetime.utcfromtimestamp(timestamp).hour

    def __t4__(self, timestamp):
        """ Week day of HTTP request 
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
            
            """
        return datetime.datetime.utcfromtimestamp(timestamp).weekday()
    
    def __str__(self):
        return """
DUMONT request at time {}:
    Length features:
        l1 = {}
        l2 = {}
        l3 = {}
        l4 = {}
        l5 = {}
    Structural features:
        s1 = {}
        s2 = {}
        s3 = {}
        s4 = {}
    Entropy features:
        e1 = {}
        e2 = {}
        e3 = {}
        e4 = {}
    Temporal features:
        t1 = {}
        t2 = {}
        t3 = {}
        t4 = {}
""".format(self.timestamp, self.l1, self.l2, self.l3, self.l4, self.l5, self.s1, self.s2, self.s3, self.s4, self.e1, self.e2, self.e3, self.e4, self.t1, self.t2, self.t3, self.t4)

    def alert(self):
        return """Alert:
    Method: {}
    User-Agent: {}
    Host: {}
    Destination IP: {}
    Constant Headers: {}
    Request size: {}
    Outgoing Info (deprecated): {}""".format(self.req.method, self.req.headers.get('user-agent', '-'), self.req.headers.get('host', '-'), '-' if self.ip == None else inet_ntoa(self.ip.dst), '[' + ', '.join(self.req.headers.keys()) + ']', self.l1, self.l1)
