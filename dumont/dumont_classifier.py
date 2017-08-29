#!/usr/bin/env python
# -*- coding: utf-8 -*-

from   sklearn     import svm
import math

class DumontClassifier:
    
    def __init__(self, fp=0.001, alpha=0.8):
        """ Dumont classifier for single feature vector.
            
            Parameters
            ----------
            fp : float, default=0.001
                Acceptable false positive rate
                
            alpha : float, default=0.01
            
            """
        self.fp = fp
        self.alpha = alpha
        self.clf = svm.OneClassSVM(kernel='rbf')
        self.width = None
    
    def fit(self, data):
        """ Fit the classifier with the data and the given false-positive rate.
            
            Parameters
            ----------
            data : list of DumontRequest
                data used to fit the classifier.
                
            """
        self.clf.fit(data)
        distances = sorted(self.clf.decision_function(data))
        border = min(len(distances)-1, int(math.ceil(len(distances)*(1-self.fp))))
        self.width = distances[border][0]
        
    def calibrate(self, normal, anomalous):
        """ Calibrate the classifier with both normal and anomalous data.
            
            Parameters
            ----------
            normal : list of DumontRequest
                benign data to calibrate the classifier.
                
            anomalous : list of DumontRequest
                malicious data to calibrate the classifier.
            
            """
        normal = self.clf.decision_function(normal)
        anomalous = self.clf.decision_function(anomalous)
        normal = map(lambda entry: (entry[0], 0), normal)
        anomalous = map(lambda entry: (entry[0], 1), anomalous)
        total = sorted(normal + anomalous, key=lambda tup: tup[0])
        
        p = len(normal)
        n = len(anomalous)
        tp = 0
        fp = 0
        
        smallestDistance = float('inf')
        threshold = 0
        
        for entry in total:
            distance = entry[0]
            positive = entry[1] == 0
            
            if positive:
                tp += 1
            else:
                fp += 1
                
            y = float(tp)/p # True positive rate
            x = float(fp)/n # False positive rate
            d = self.__distance__(x, y)
            if d < smallestDistance:
                smallestDistance = d
                threshold = distance
            
        self.width = threshold
        
    def predict(self, data):
        """ Predict data based on the fitted model
            
            Parameters
            ----------
            data : list of DumontRequest()
                list of requests to predict.
            
            Returns
            -------
            result : list of Boolean
                list of booleans where True indicates the request on that position
                was benign and False indicates the request was Malicious.
            """
        distance = self.clf.decision_function(data)
        return list(map(lambda entry: entry[0] <= self.width, distance))
    
    def __distance__(self, x, y):
        """ Auxilliary method to compute the distance between x and y.
            
            Parameters
            ----------
            x : coordinate
                x coordinate
                
            y : coordinate
                y coordinate
                
            Returns
            -------
            result : float
                distance between x and y
                
            """
        x0 = x
        y0 = y
        x1 = 0
        y1 = 1
        x2 = 1
        y2 = 1+self.alpha
        
        return float(abs((y2-y1)*x0 - (x2-x1)*y0 + x2*y2 - y2*x1)) /\
                math.sqrt((y2-y1)**2 + (x2-x1)**2)
