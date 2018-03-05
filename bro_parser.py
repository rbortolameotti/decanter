from __future__ import division
from brothon import bro_log_reader
import pandas as pd

class BroParser:
    """ Parse Bro log files """ 
    
    def __init__(self):
        pass
    
    def parseFile(self, filename):
        """ Creates a pandas dataframe from given brofile
            
            Parameters
            ----------
            filename : string
                Path to file to be parsed
                
            Returns
            -------
            result : pd.DataFrame
                Pandas dataframe containing bro log file
            """
        bro_log = bro_log_reader.BroLogReader(filename)
        data = pd.DataFrame(bro_log.readrows())
        data['header_values'] = data['header_values'].apply(self.__parseHeaderValues__)
        return data
    
    def __parseHeaderValues__(self, headerValues):
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
        try:
		    return dict((x, y) for x, y in list(map( lambda entry:(entry.split('||')[0].lower(), entry.split('||')[1].replace('\\x2c', ',')),headerValues.split(','))))
        except:
		    return {}


