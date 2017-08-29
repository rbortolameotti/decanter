#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dumont_request import DumontRequest
import dpkt

def parsePCAP(filename):
    """ Generate a list of Dumont Requests from a pcap file 
        
        Parameters
        ----------
        filename : string
            path to .pcap file to parse.
        
        Returns
        -------
        result : list of DumontRequest()
            ordered list of dumont requests.
            
        """
    DumontRequests = []
    
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Check for TCP in the transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):

            # Set the TCP data
            tcp = ip.data

            # Now see if we can parse the contents as an HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            DumontRequests.append(DumontRequest(timestamp, request, ip))
    
    return aggregateTemporalFeatures(DumontRequests)
    
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
