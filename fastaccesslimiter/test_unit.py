#!/usr/bin/env python3
import unittest, json, os
from fastaccesslimiter import FastAccessLimiter

class TestFastAccessLimiter(unittest.TestCase):
    def test_01_ip_network_list_empty(self):
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),0)
        
    def test_02_add_ip_network_list(self):
        accessLimiter.add_ip('10.0.0.0/8')
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),1)

    def test_03_add_ip_network_list(self): # guarantee there is no duplicated CIDRs
        accessLimiter.add_ip('10.0.0.0/8')
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),1)
            
    def test_04_extend_ip_network_list(self):
        accessLimiter.extend_ip_network_list(['1.2.3.4/32','4.5.6.7/32'])
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),3)
    
    def test_05_save_ip_network_list(self):
        accessLimiter.save_ip_network_list(test_rules_file)
        self.assertTrue(os.path.exists(test_rules_file))
        
    def test_06_save_ip_network_list(self):
        accessLimiter.save_ip_network_list(test_rules_filegz)
        self.assertTrue(os.path.exists(test_rules_filegz))
        
    def test_07_load_ip_network_list(self):
        accessLimiter.load_ip_network_list(['1.1.1.1','2.2.2.2'])
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),2)
            
    def test_09_open_ip_network_list(self):
        accessLimiter.open_ip_network_list(test_rules_file)
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),3)
            
    def test_10_open_ip_network_list_gzipped(self):
        accessLimiter.open_ip_network_list(test_rules_filegz)
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),3)

    def test_11_remove_ip_network_list(self):
        result = accessLimiter.remove_ip('11.11.11.11/32')
        self.assertFalse(result)

    def test_12_remove_ip_network_list(self):
        result = accessLimiter.remove_ip('4.5.6.7')
        self.assertTrue(result)

    def test_13_ip_network_list_length(self):
        current_list = accessLimiter.get_ip_network_list()
        self.assertEqual(len(current_list),2)

    def test_14_check_ip_access(self):
        result = accessLimiter('1.2.3.4')
        self.assertTrue(result)
        self.assertEqual('1.2.3.4/32',result)

    def test_14_check_ip_access(self):
        result = accessLimiter('5.6.7.8')
        self.assertFalse(result)

    def test_15_stats(self):
        result = accessLimiter('1.2.3.4')
        self.assertTrue(result)
        stats = accessLimiter.stats_info()
        self.assertEqual(stats.hits,1)
        self.assertEqual(stats.top_hits['1.2.3.4'],1)
        accessLimiter.stats_reset()
        stats = accessLimiter.stats_info()
        self.assertEqual(stats.hits,0)

if __name__ == '__main__':
    test_rules_file = '/tmp/fastaccesslimiter_unit_test.json'
    test_rules_filegz = test_rules_file+'.gz'
    accessLimiter = FastAccessLimiter(with_stats=True)
    unittest.main(verbosity=2)
    os.remove(test_rules_file)
