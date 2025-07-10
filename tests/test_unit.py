#!/usr/bin/env python3
import unittest, json, os
from fastaccesslimiter.compat import FastAccessLimiter as FastAccessLimiterV1
from fastaccesslimiter import FastAccessLimiter as FastAccessLimiterV2

class TestFastAccessLimiterV1Compat(unittest.TestCase):
    def setUp(self):
        self.test_rules_file = '/tmp/fastaccesslimiter_unit_test.json'
        self.test_rules_filegz = self.test_rules_file + '.gz'
        
    def test_01_ip_network_list_empty(self):
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),0)
        
    def test_02_add_ip_network_list(self):
        access_limiter_v1.add_ip('10.0.0.0/8')
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),1)

    def test_03_add_ip_network_list(self): # guarantee there is no duplicated CIDRs
        access_limiter_v1.add_ip('10.0.0.0/8')
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),1)
            
    def test_04_extend_ip_network_list(self):
        access_limiter_v1.extend_ip_network_list(['1.2.3.4/32','4.5.6.7/32'])
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),3)
    
    def test_05_save_ip_network_list(self):
        access_limiter_v1.save_ip_network_list(self.test_rules_file)
        self.assertTrue(os.path.exists(self.test_rules_file))
        
    def test_06_save_ip_network_list(self):
        access_limiter_v1.save_ip_network_list(self.test_rules_filegz)
        self.assertTrue(os.path.exists(self.test_rules_filegz))
        
    def test_07_load_ip_network_list(self):
        access_limiter_v1.load_ip_network_list(['1.1.1.1','2.2.2.2'])
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),2)
            
    def test_08_open_ip_network_list(self):
        access_limiter_v1.open_ip_network_list(self.test_rules_file)
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),3)
            
    def test_09_open_ip_network_list_gzipped(self):
        access_limiter_v1.open_ip_network_list(self.test_rules_filegz)
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),3)

    def test_10_remove_ip_network_list(self):
        result = access_limiter_v1.remove_ip('11.11.11.11/32')
        self.assertFalse(result)

    def test_11_remove_ip_network_list(self):
        result = access_limiter_v1.remove_ip('4.5.6.7/32')
        self.assertTrue(result)

    def test_12_ip_network_list_length(self):
        current_list = access_limiter_v1.get_ip_network_list()
        self.assertEqual(len(current_list),2)

    def test_13_check_ip_access(self):
        result = access_limiter_v1('1.2.3.4')
        self.assertTrue(result)
        self.assertEqual('1.2.3.4/32',result)

    def test_14_check_ip_access(self):
        result = access_limiter_v1('5.6.7.8')
        self.assertFalse(result)

    def test_15_stats(self):
        result = access_limiter_v1('1.2.3.4')
        self.assertTrue(result)
        stats = access_limiter_v1.stats_info()
        self.assertEqual(stats.hits,2)
        self.assertEqual(stats.top_hits['1.2.3.4'],2)
        access_limiter_v1.stats_reset()
        stats = access_limiter_v1.stats_info()
        self.assertEqual(stats.hits,0)

class TestFastAccessLimiterV2(unittest.TestCase):
    def setUp(self):
        # access_limiter_v2 = FastAccessLimiterV2(ip_networks_list=[], with_stats=True, normalize_invalid_cidr=True)
        self.test_rules_file = '/tmp/fastaccesslimiter_unit_test.json'
        self.test_rules_filegz = self.test_rules_file + '.gz'

    def test_01_ip_network_list_empty(self):
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),0)
        
    def test_02_add_ip_network(self):
        access_limiter_v2.add_ip_network('10.0.0.0/8')
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),1)

    def test_03_add_ip_network(self): # guarantee there is no duplicated CIDRs
        access_limiter_v2.add_ip_network('10.0.0.0/8')
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),1)

    def test_04_add_ip_networks_list(self):
        access_limiter_v2.add_ip_networks_list(['1.2.3.4/32','4.5.6.7/32'])
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),3)

    def test_05_save_ip_networks_list(self):
        access_limiter_v2.save_ip_networks_list(self.test_rules_file)
        self.assertTrue(os.path.exists(self.test_rules_file))

    def test_06_save_ip_networks_list(self):
        access_limiter_v2.save_ip_networks_list(self.test_rules_filegz)
        self.assertTrue(os.path.exists(self.test_rules_filegz))

    def test_07_set_ip_networks_list(self):
        access_limiter_v2.set_ip_networks_list(['1.1.1.1','2.2.2.2'])
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),2)

    def test_08_open_ip_networks_list(self):
        access_limiter_v2.open_ip_networks_list(self.test_rules_file)
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),3)

    def test_09_open_ip_networks_list_gzipped(self):
        access_limiter_v2.open_ip_networks_list(self.test_rules_filegz)
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),3)

    def test_10_remove_ip_network_list(self):
        result = access_limiter_v2.remove_ip_network('11.11.11.11/32')
        self.assertFalse(result)

    def test_11_remove_ip_network_list(self):
        result = access_limiter_v2.remove_ip_network('4.5.6.7')
        self.assertTrue(result)

    def test_12_ip_network_list_length(self):
        current_list = access_limiter_v2.get_ip_networks_list()
        self.assertEqual(len(current_list),2)

    def test_13_check_ip_access(self):
        result = access_limiter_v2('1.2.3.4')
        self.assertTrue(result)
        self.assertEqual('1.2.3.4/32',result)

    def test_14_check_ip_access(self):
        result = access_limiter_v2('5.6.7.8')
        self.assertFalse(result)

    def test_15_stats(self):
        result = access_limiter_v2('1.2.3.4')
        self.assertTrue(result)
        stats = access_limiter_v2.stats_info()
        self.assertEqual(stats.hits,2)
        self.assertEqual(stats.top_hits['1.2.3.4'],2)
        access_limiter_v2.stats_reset()
        stats = access_limiter_v2.stats_info()
        self.assertEqual(stats.hits,0)
        
if __name__ == '__main__':
    # self.test_rules_file = '/tmp/fastaccesslimiter_unit_test.json'
    # self.test_rules_filegz = self.test_rules_file+'.gz'
    # accessLimiter = FastAccessLimiter(ip_networks_list=[],with_stats=True)
    access_limiter_v1 = FastAccessLimiterV1(ip_network_list=[], with_stats=True)
    access_limiter_v2 = FastAccessLimiterV2(ip_networks_list=[], with_stats=True, normalize_invalid_cidr=True)
    
    unittest.main(verbosity=2,failfast=True,catchbreak=True)
