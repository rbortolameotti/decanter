from detection import DetectionModule

class EvaluationUtils:
    def __init__(self, alerts, benign):
        self.alerts = alerts
        self.benign = benign
        self.unique_fing = self._unique_fingerprints()
    
    # TODO : Add the detection performance according to the requests numbers and not fingerprints.!! TODOOOO!
    def detection_performance(self):
        tp = 0
        tn = 0
        fp = 0
        fn = 0
        
        for a in self.alerts:
            if int(a.is_malicious) == 1:
                tp += 1
            else:
                fp += 1
        
        for b in self.benign:
            if int(b.is_malicious) == 1:
                fn += 1
            else:
                tn += 1
                
        print """
            *************************************
                    Detection Performance 
            *************************************
                Malicious              Benign
            -------------------     -------------------
            True positives:  {}     True negatives:  {}
            False negatives: {}     False positives: {}
        """.format(tp, tn, fn, fp)
        
        return tp, fn, tn, fp
    
    
        # TODO : Add the detection performance according to the requests numbers and not fingerprints.!! TODOOOO!
    def detection_performance_2(self):
        tp = []
        tn = []
        fp = []
        fn = []
        
        for a in self.alerts:
            if int(a.is_malicious) == 1:
                tp.append(a)
            else:
                fp.append(a)
        
        for b in self.benign:
            if int(b.is_malicious) == 1:
                fn.append(b)
            else:
                tn.append(b)
                
        tp_fings = len(tp)
        tn_fings = len(tn)
        fp_fings = len(fp)
        fn_fings = len(fn)
        
        print """
            ********************************************
                 Detection Performance - fingerprints
            ********************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(tp_fings, tn_fings, fn_fings, fp_fings)
        
        retrained_fp = []
        
        for a in self.unique_fing:
            if a in self.alerts and int(a.is_malicious) == 0:
                retrained_fp.append(a)
                
        retrained_fp_fings = len(retrained_fp)
        
        retrained_tp_fings = tp_fings
        retrained_tn_fings = tn_fings + (fp_fings - retrained_fp_fings)
        retrained_fn_fings = fn_fings
        
        
        print """
            ***************************************************************
                 Detection Performance - fingerprints - after retraining
            ***************************************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(retrained_tp_fings, retrained_tn_fings, retrained_fn_fings, retrained_fp_fings)
                
                
        tp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in tp])
        tn_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in tn])
        fp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in fp])
        fn_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in fn])
            
        print """
            ****************************************
                 Detection Performance - requests
            ****************************************
                Malicious                           Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(tp_reqs, tn_reqs, fn_reqs, fp_reqs)
        
        retrained_fp = []
        
        for a in self.unique_fing:
            if a in self.alerts and int(a.is_malicious) == 0:
                retrained_fp.append(a)
                
        retrained_fp_reqs = sum([sum([hosts[1] for hosts in fingerprint.hosts]) for fingerprint in retrained_fp])
        
        retrained_tp_reqs = tp_reqs
        retrained_tn_reqs = tn_reqs + (fp_reqs - retrained_fp_reqs)
        retrained_fn_reqs = fn_reqs
                
        
        print """
            **********************************************************
                Detection Performance - requests - after retraining
            **********************************************************
                Malicious                          Benign
            -----------------------             -----------------------
            True positives:  {:<10}         True negatives:  {:<10}
            False negatives: {:<10}         False positives: {:<10}
        """.format(retrained_tp_reqs, retrained_tn_reqs, retrained_fn_reqs, retrained_fp_reqs)
        
        return tp_reqs, tn_reqs, fn_reqs, fp_reqs
        
        
    def output_requests(self):
        req_alerts      = 0
        req_benign      = 0
        req_uniq_alerts = 0
        
        for f in self.alerts:
            for domain, number_req in f.hosts:
                req_alerts += number_req
        
        for f in self.benign:
            for domain, number_req in f.hosts:
                req_benign += number_req
                
        for f in self.unique_fing:
            for domain, number_req in f.hosts:
                req_uniq_alerts += number_req
                
        print """
            *************************************
                      Fingerprints Stats
            *************************************
            Benign Fingerprints: {}
            Alerts Fingerprints: {}
            ----> Unique Alerts: {}
            
            *************************************
                        Requests Stats
            *************************************
            Benign Requests:              {}
            Alerts Requests:              {}
            ----> Unique Alerts Requests: {}
        """.format(len(self.benign), len(self.alerts), len(self.unique_fing), req_benign, req_alerts, req_uniq_alerts)
        
        
    def _unique_fingerprints(self):
        '''
            This method identifies the set of unique alerts. We assume an operator would add the fingerprints
            of false positives to the set of trained fingerprints, to avoid false positives in the future.
            
            We identify two fingerprints as similar, the same we do it in the detection module.
            
            Param
            ---------
            return:
                Set of unique Fingerprints. 
        '''
        detector = DetectionModule()
        unique_alerts = []
        
        if self.alerts:
            unique_alerts.append(self.alerts[0])
            
        for i in range(1, len(self.alerts)):
            res = False
            for uniq_a in unique_alerts:
                if detector.similarity_check(self.alerts[i], uniq_a):
                    res = True
            if res == False:
                unique_alerts.append(self.alerts[i])
            
        return unique_alerts
            

