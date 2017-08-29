#!/usr/bin/env python
# -*- coding: utf-8 -*-

from   collections import Counter
from   scipy.stats import entropy
import datetime
import urlparse

class DumontLog:
    
    def __init__(self, log):
        """ A DumontLog instance requires a timestamp
            and the HTTP log it calculates the length
            (l1-l5), structural (s1-s4), entropy (e1-e4),
            and temporal features (t1-t4) accordingly. 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        self.timestamp = log['ts']
        self.log = log
        
        # Set length features of log
        self.l1 = self.__l1__(self.log)
        self.l2 = self.__l2__(self.log)
        self.l3 = self.__l3__(self.log)
        self.l4 = self.__l4__(self.log)
        self.l5 = self.__l5__(self.log)
        
        # Set structural features of log
        self.s1 = self.__s1__(self.log)
        self.s2 = self.__s2__(self.log)
        self.s3 = self.__s3__(self.log)
        self.s4 = self.__s4__(self.log)
        
        # Set entropy features of log
        self.e1 = self.__e1__(self.log)
        self.e2 = self.__e2__(self.log)
        self.e3 = self.__e3__(self.log)
        self.e4 = self.__e4__(self.log)
        
        # Set temporal features of log
        self.t1 = self.__t1__(self.timestamp)
        self.t2 = self.__t2__(self.log)
        self.t3 = self.__t3__(self.timestamp)
        self.t4 = self.__t4__(self.timestamp)
        
        # Identifier if log is malicious
        self.is_malicious = log.get('is_malicious', 0) == '1'
    
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
    
    """ Extract length features of HTTP log """
    def __l1__(self, log):
        """ Extracts length of log
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        total_length = 0
        # Add method length
        total_length += len(log['method'])
        # Add URI length
        total_length += len(log['uri'])
        # Add header length
        total_length += sum([len(k)+len(v) for k, v in log['header_values'].items()])
        # Add body length
        total_length += log['request_body_len']
        
        return total_length

    def __l2__(self, log):
        """ Extract total length of URI 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        return len(log['uri'])

    def __l3__(self, log):
        """ Total length of URI parameters 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        parsed = urlparse.urlparse(log['uri'])
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += len(key)
            length += sum([len(v) for v in value])
        return length

    def __l4__(self, log):
        """ Total length of headers 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        return sum([len(k)+len(v) for k, v in log['header_values'].items()])
    
    def __l5__(self, log):
        """ Length of request body 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        return log['request_body_len']

    """ Extract structural features of HTTP logs """
    
    def __s1__(self, log):
        """ Extract average length of URI parameter names
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        parsed = urlparse.urlparse(log['uri'])
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += len(key)
        return float(length)/len(queryDict) if length != 0 else 0

    def __s2__(self, log):
        """ Average length of URI parameter values
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        parsed = urlparse.urlparse(log['uri'])
        queryDict = urlparse.parse_qs(parsed.query)
        length = 0
        for key, value in queryDict.items():
            length += sum([len(v) for v in value])
        return float(length)/len(queryDict) if length != 0 else 0

    def __s3__(self, log):
        """ Average length of header names
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        length = 0
        for key, value in log['header_values'].items():
            length += len(key)
        return float(length)/len(log['header_values']) if length != 0 else 0

    def __s4__(self, log):
        """ Average length of header values 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        length = 0
        for key, value in log['header_values'].items():
            length += len(value)
        return float(length)/len(log['header_values']) if length != 0 else 0

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

    def __e1__(self, log):
        """ 8-bit entropy of log 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        # Extract full header from log
        header = ''
        header += str(log['method']) + ' ' + str(log['uri']) + ' HTTP/' + log['version'] + '\r\n'
        header += '\r\n'.join([k + ': ' + v for k, v in log['header_values'].items()]) + '\r\n'
        
        # Transform request into byte array
        reqBytes = [ord(c) for c in str(header)]
        # Compute entropy from bytes
        return self.__entropyFromList__(reqBytes)

    def __e2__(self, log):
        """ 16-bit entropy of log 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        # Extract full header from log
        header = ''
        header += str(log['method']) + ' ' + str(log['uri']) + ' HTTP/' + log['version'] + '\r\n'
        header += '\r\n'.join([k + ': ' + v for k, v in log['header_values'].items()]) + '\r\n'
        
        # Transform request into byte array
        reqBytes = [ord(c) for c in str(header)]
        # Combine two bites into 16 bit number
        entr16 = [reqBytes[i]<<8 + reqBytes[i+1] for i in range(0, len(reqBytes)-1, 2)]
        # Compute entropy from bytes
        return self.__entropyFromList__(entr16)

    def __e3__(self, log):
        """ 24-bit entropy of log 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        # Extract full header from log
        header = ''
        header += str(log['method']) + ' ' + str(log['uri']) + ' HTTP/' + log['version'] + '\r\n'
        header += '\r\n'.join([k + ': ' + v for k, v in log['header_values'].items()]) + '\r\n'
        
        # Transform request into byte array
        reqBytes = [ord(c) for c in str(header)]
        # Combine two bites into 16 bit number
        entr24 = [reqBytes[i]<<16 + reqBytes[i+1]<<8 + reqBytes[i+2] for i in range(0, len(reqBytes)-2, 3)]
        # Compute entropy from bytes
        return self.__entropyFromList__(entr24)

    def __e4__(self, log):
        """ 32-bit entropy of log 
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
            
            """
        # Extract full header from log
        header = ''
        header += str(log['method']) + ' ' + str(log['uri']) + ' HTTP/' + log['version'] + '\r\n'
        header += '\r\n'.join([k + ': ' + v for k, v in log['header_values'].items()]) + '\r\n'
        
        # Transform request into byte array
        reqBytes = [ord(c) for c in str(header)]
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
        timestamp = (timestamp - datetime.datetime.utcfromtimestamp(0)).total_seconds()
        return datetime.datetime.utcfromtimestamp(timestamp)

    def __t2__(self, log):
        """ Number of bytes in last minute 
            
            Note this method differs from the paper, since
            only a single packet is processed at the time
            features within a timeframe whould be acumulated,
            hence we calculate the number of bytes instead of t2
            
            Parameters
            ----------
            log : pandas.core.series.Series
                Bro log retrieved from .log file.
                
            """
        return self.__l1__(log)

    def __t3__(self, timestamp):
        """ Hour of HTTP request 
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
                
            """
        timestamp = (timestamp - datetime.datetime.utcfromtimestamp(0)).total_seconds()
        return datetime.datetime.utcfromtimestamp(timestamp).hour

    def __t4__(self, timestamp):
        """ Week day of HTTP request 
            
            Parameters
            ----------
            timestamp : timestamp
                timestamp of request
            
            """
        timestamp = (timestamp - datetime.datetime.utcfromtimestamp(0)).total_seconds()
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
    Outgoing Info (deprecated): {}""".format(self.log['method'], self.log['header_values'].get('user-agent', '-'), self.log['header_values'].get('host', '-'), self.log['id.resp_h'], '[' + ', '.join(self.log['header_values'].keys()) + ']', self.l1, self.l1)
