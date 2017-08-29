#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dumont_classifier import DumontClassifier

class DumontDetector:
    
    def __init__(self, fp=0.001, alpha=0.4):
        """ Constructor creates all necessary OneClassSVM instances.
            
            Parameters
            ----------
            fp : float, default=0.001
                Acceptable false positive rate
                
            """
        self.fp = fp
        self.star = DumontClassifier(fp, alpha)
        self.l_star = DumontClassifier(fp, alpha)
        self.s_star = DumontClassifier(fp, alpha)
        self.e_star = DumontClassifier(fp, alpha)
        self.t_star = DumontClassifier(fp, alpha)
        self.l1 = DumontClassifier(fp, alpha)
        self.l2 = DumontClassifier(fp, alpha)
        self.l3 = DumontClassifier(fp, alpha)
        self.l4 = DumontClassifier(fp, alpha)
        self.l5 = DumontClassifier(fp, alpha)
        self.s1 = DumontClassifier(fp, alpha)
        self.s2 = DumontClassifier(fp, alpha)
        self.s3 = DumontClassifier(fp, alpha)
        self.s4 = DumontClassifier(fp, alpha)
        self.e1 = DumontClassifier(fp, alpha)
        self.e2 = DumontClassifier(fp, alpha)
        self.e3 = DumontClassifier(fp, alpha)
        self.e4 = DumontClassifier(fp, alpha)
        self.t1 = DumontClassifier(fp, alpha)
        self.t2 = DumontClassifier(fp, alpha)
        self.t3 = DumontClassifier(fp, alpha)
        self.t4 = DumontClassifier(fp, alpha)
        
    def fit(self, data):
        """ Method to fit data into DumontDetector
            
            Parameters
            ----------
            data : list of DumontRequest
                data used to fit the classifiers.
            
            """
        self.star.fit(self.__extractFeatureVector__(data))
        self.l_star.fit(self.__extractFeatureVectorL__(data))
        self.s_star.fit(self.__extractFeatureVectorS__(data))
        self.e_star.fit(self.__extractFeatureVectorE__(data))
        self.t_star.fit(self.__extractFeatureVectorT__(data))
        self.l1.fit(self.__extractFeatureL1__(data))
        self.l2.fit(self.__extractFeatureL2__(data))
        self.l3.fit(self.__extractFeatureL3__(data))
        self.l4.fit(self.__extractFeatureL4__(data))
        self.l5.fit(self.__extractFeatureL5__(data))
        self.s1.fit(self.__extractFeatureS1__(data))
        self.s2.fit(self.__extractFeatureS2__(data))
        self.s3.fit(self.__extractFeatureS3__(data))
        self.s4.fit(self.__extractFeatureS4__(data))
        self.e1.fit(self.__extractFeatureE1__(data))
        self.e2.fit(self.__extractFeatureE2__(data))
        self.e3.fit(self.__extractFeatureE3__(data))
        self.e4.fit(self.__extractFeatureE4__(data))
        self.t1.fit(self.__extractFeatureT1__(data))
        self.t2.fit(self.__extractFeatureT2__(data))
        self.t3.fit(self.__extractFeatureT3__(data))
        self.t4.fit(self.__extractFeatureT4__(data))
    
    def predict(self, data):    
        """ Method which classifies all elements
            in data into anomaly (False) or not (True) 
            
            Parameters
            ----------
            data : list of DumontRequest
                data used to fit the classifiers.
                
            Returns
            -------
            result : list of Boolean
                list of booleans where True indicates the request on that position
                was benign and False indicates the request was Malicious.
            
            """    
        result = self.star.predict(self.__extractFeatureVector__(data))
        result = self.__listAnd__(result, self.l_star.predict(self.__extractFeatureVectorL__(data)))     
        result = self.__listAnd__(result, self.s_star.predict(self.__extractFeatureVectorS__(data)))
        result = self.__listAnd__(result, self.e_star.predict(self.__extractFeatureVectorE__(data)))
        result = self.__listAnd__(result, self.t_star.predict(self.__extractFeatureVectorT__(data)))
        result = self.__listAnd__(result, self.l1.predict(self.__extractFeatureL1__(data)))
        result = self.__listAnd__(result, self.l2.predict(self.__extractFeatureL2__(data)))
        result = self.__listAnd__(result, self.l3.predict(self.__extractFeatureL3__(data)))
        result = self.__listAnd__(result, self.l4.predict(self.__extractFeatureL4__(data)))
        result = self.__listAnd__(result, self.l5.predict(self.__extractFeatureL5__(data)))
        result = self.__listAnd__(result, self.s1.predict(self.__extractFeatureS1__(data)))
        result = self.__listAnd__(result, self.s2.predict(self.__extractFeatureS2__(data)))
        result = self.__listAnd__(result, self.s3.predict(self.__extractFeatureS3__(data)))
        result = self.__listAnd__(result, self.s4.predict(self.__extractFeatureS4__(data)))
        result = self.__listAnd__(result, self.e1.predict(self.__extractFeatureE1__(data)))
        result = self.__listAnd__(result, self.e2.predict(self.__extractFeatureE2__(data)))
        result = self.__listAnd__(result, self.e3.predict(self.__extractFeatureE3__(data)))
        result = self.__listAnd__(result, self.e4.predict(self.__extractFeatureE4__(data)))
        result = self.__listAnd__(result, self.t1.predict(self.__extractFeatureT1__(data)))
        result = self.__listAnd__(result, self.t2.predict(self.__extractFeatureT2__(data)))
        result = self.__listAnd__(result, self.t3.predict(self.__extractFeatureT3__(data)))
        result = self.__listAnd__(result, self.t4.predict(self.__extractFeatureT4__(data)))
        
        return result
    
    def calibrate(self, normal, anomalous):
        """ Calibrate the classifiers with both normal and anomalous data.
            
            Parameters
            ----------
            normal : list of DumontRequest
                benign data to calibrate the classifier.
                
            anomalous : list of DumontRequest
                malicious data to calibrate the classifier.
            
            """
        self.star.calibrate(self.__extractFeatureVector__(normal),\
                            self.__extractFeatureVector__(anomalous))
        self.l_star.calibrate(self.__extractFeatureVectorL__(normal),\
                              self.__extractFeatureVectorL__(anomalous))
        self.s_star.calibrate(self.__extractFeatureVectorS__(normal),\
                              self.__extractFeatureVectorS__(anomalous))
        self.e_star.calibrate(self.__extractFeatureVectorE__(normal),\
                              self.__extractFeatureVectorE__(anomalous))
        self.t_star.calibrate(self.__extractFeatureVectorT__(normal),\
                              self.__extractFeatureVectorT__(anomalous))
        self.l1.calibrate(self.__extractFeatureL1__(normal),\
                          self.__extractFeatureL1__(anomalous))
        self.l2.calibrate(self.__extractFeatureL2__(normal),\
                          self.__extractFeatureL2__(anomalous))
        self.l3.calibrate(self.__extractFeatureL3__(normal),\
                          self.__extractFeatureL3__(anomalous))
        self.l4.calibrate(self.__extractFeatureL4__(normal),\
                          self.__extractFeatureL4__(anomalous))
        self.l5.calibrate(self.__extractFeatureL5__(normal),\
                          self.__extractFeatureL5__(anomalous))
        self.s1.calibrate(self.__extractFeatureS1__(normal),\
                          self.__extractFeatureS1__(anomalous))
        self.s2.calibrate(self.__extractFeatureS2__(normal),\
                          self.__extractFeatureS2__(anomalous))
        self.s3.calibrate(self.__extractFeatureS3__(normal),\
                          self.__extractFeatureS3__(anomalous))
        self.s4.calibrate(self.__extractFeatureS4__(normal),\
                          self.__extractFeatureS4__(anomalous))
        self.e1.calibrate(self.__extractFeatureE1__(normal),\
                          self.__extractFeatureE1__(anomalous))
        self.e2.calibrate(self.__extractFeatureE2__(normal),\
                          self.__extractFeatureE2__(anomalous))
        self.e3.calibrate(self.__extractFeatureE3__(normal),\
                          self.__extractFeatureE3__(anomalous))
        self.e4.calibrate(self.__extractFeatureE4__(normal),\
                          self.__extractFeatureE4__(anomalous))
        self.t1.calibrate(self.__extractFeatureT1__(normal),\
                          self.__extractFeatureT1__(anomalous))
        self.t2.calibrate(self.__extractFeatureT2__(normal),\
                          self.__extractFeatureT2__(anomalous))
        self.t3.calibrate(self.__extractFeatureT3__(normal),\
                          self.__extractFeatureT3__(anomalous))
        self.t4.calibrate(self.__extractFeatureT4__(normal),\
                          self.__extractFeatureT4__(anomalous))
    
    """ Auxiliary method to perform AND operation
        on all pairs in two boolean lists. """
    def __listAnd__(self, x, y):
        return [a and b for a, b in zip(x, y)]
    
    """ Method to predict whether data is normal or anomaly """
    def __predictCLF__(self, clf, width, data):
        distance = clf.decision_function(data)
        return list(map(lambda entry: entry <= width, distance))
    
    """ Method to extract complete feature vector
        from supplied DUMONT request data """
    def __extractFeatureVector__(self, data):
        return list(map(lambda req: req.featureVector(), data))
    
    """ Method to extract feature vector L
        from supplied DUMONT request data """
    def __extractFeatureVectorL__(self, data):
        return list(map(lambda req: req.featureVectorL(), data))
    
    """ Method to extract feature vector S
        from supplied DUMONT request data """
    def __extractFeatureVectorS__(self, data):
        return list(map(lambda req: req.featureVectorS(), data))
    
    """ Method to extract feature vector E
        from supplied DUMONT request data """
    def __extractFeatureVectorE__(self, data):
        return list(map(lambda req: req.featureVectorE(), data))
    
    """ Method to extract feature vector T
        from supplied DUMONT request data """
    def __extractFeatureVectorT__(self, data):
        return list(map(lambda req: req.featureVectorT(), data))
    
    """ Method to extract feature l1
        from supplied DUMONT request data"""
    def __extractFeatureL1__(self, data):
        return list(map(lambda req: [req.l1], data))
    
    """ Method to extract feature l2
        from supplied DUMONT request data"""
    def __extractFeatureL2__(self, data):
        return list(map(lambda req: [req.l2], data))
    
    """ Method to extract feature l3
        from supplied DUMONT request data"""
    def __extractFeatureL3__(self, data):
        return list(map(lambda req: [req.l3], data))
    
    """ Method to extract feature l4
        from supplied DUMONT request data"""
    def __extractFeatureL4__(self, data):
        return list(map(lambda req: [req.l4], data))
    
    """ Method to extract feature l5
        from supplied DUMONT request data"""
    def __extractFeatureL5__(self, data):
        return list(map(lambda req: [req.l5], data))
    
    """ Method to extract feature s1
        from supplied DUMONT request data"""
    def __extractFeatureS1__(self, data):
        return list(map(lambda req: [req.s1], data))
    
    """ Method to extract feature s2
        from supplied DUMONT request data"""
    def __extractFeatureS2__(self, data):
        return list(map(lambda req: [req.s2], data))
    
    """ Method to extract feature s3
        from supplied DUMONT request data"""
    def __extractFeatureS3__(self, data):
        return list(map(lambda req: [req.s3], data))
    
    """ Method to extract feature s4
        from supplied DUMONT request data"""
    def __extractFeatureS4__(self, data):
        return list(map(lambda req: [req.s4], data))
    
    """ Method to extract feature e1
        from supplied DUMONT request data"""
    def __extractFeatureE1__(self, data):
        return list(map(lambda req: [req.e1], data))
    
    """ Method to extract feature e2
        from supplied DUMONT request data"""
    def __extractFeatureE2__(self, data):
        return list(map(lambda req: [req.e2], data))
    
    """ Method to extract feature e3
        from supplied DUMONT request data"""
    def __extractFeatureE3__(self, data):
        return list(map(lambda req: [req.e3], data))
    
    """ Method to extract feature e4
        from supplied DUMONT request data"""
    def __extractFeatureE4__(self, data):
        return list(map(lambda req: [req.e4], data))
    
    """ Method to extract feature t1
        from supplied DUMONT request data"""
    def __extractFeatureT1__(self, data):
        return list(map(lambda req: [req.t1], data))
    
    """ Method to extract feature t2
        from supplied DUMONT request data"""
    def __extractFeatureT2__(self, data):
        return list(map(lambda req: [req.t2], data))
    
    """ Method to extract feature t3
        from supplied DUMONT request data"""
    def __extractFeatureT3__(self, data):
        return list(map(lambda req: [req.t3], data))
    
    """ Method to extract feature t4
        from supplied DUMONT request data"""
    def __extractFeatureT4__(self, data):
        return list(map(lambda req: [req.t4], data))
