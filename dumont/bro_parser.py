#!/usr/bin/env python
# -*- coding: utf-8 -*-

from   .dumont_log import DumontLog
from   brothon     import bro_log_reader
import pandas as pd

def parseLOG(filename):
    """ Generate a list of Dumont Requests from a bro log file 
        
        Parameters
        ----------
        filename : string
            path to .pcap file to parse.
        
        Returns
        -------
        result : list of DumontLog()
            ordered list of dumont logs.
            
        """
    DumontRequests = []
    
    bro_log = bro_log_reader.BroLogReader(filename)
    data = pd.DataFrame(bro_log.readrows())
    data['header_values'] = data['header_values'].apply(__parseHeaderValues__)
    
    for d in data.iterrows():
        if d[1]['method'] == 'GET' or  d[1]['method'] == 'POST':
            DumontRequests.append(DumontLog(d[1]))
        
    return aggregateTemporalFeatures(DumontRequests)
    
def __parseHeaderValues__(headerValues):
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
        return  dict((x, y) for x, y in\
                list(map(\
                lambda entry: (entry.split('||')[0].lower(), entry.split('||')[1].replace('\\x2c', ',')),\
                headerValues.split(','))))
    
def aggregateTemporalFeatures(DumontRequests):
    """ Auxiliary method to aggregate t1 and t2 features of Dumont requests 
        
        Parameters
        ----------
        DumontRequests : list of DumontRequest
            ordered list of dumont requests.      
        
        Returns
        -------
        DumontRequests : list of DumontRequest
            ordered list of dumont requests where temporal features are aggregated.            
        
        """
    i = 0
    while i < len(DumontRequests):
        start = i
        end = i
        currentDate = DumontRequests[i].t1
        
        # Check for same minute
        while end < len(DumontRequests) and\
              currentDate.date() == DumontRequests[end].t1.date() and\
              currentDate.hour == DumontRequests[end].t1.hour and\
              currentDate.minute == DumontRequests[end].t1.minute:
            end += 1
            
        total = 0
        # For all DumontRequests within the same minute:
        # - set the number of requests t1
        # - Calculate total number of outbound bytes t2
        for j in range(start, end):
            DumontRequests[j].t1 = end-start
            total += DumontRequests[j].t2
            
        # For all DumontRequests within the same minute:
        # - set the number of outbound bytes t2
        # After finishing t2 is set for all Dumont Requests
        for j in range(start, end):
            DumontRequests[j].t2 = total
        
        i = max(end, i+1)
    return DumontRequests
