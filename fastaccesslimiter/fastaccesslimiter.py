#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fast Access Limiter v1.0.0 - A complete and fast IP address access limiter for Python."""
"""
 ______        _                                     _      _           _ _
|  ____|      | |       /\                          | |    (_)         (_) |
| |__ __ _ ___| |_     /  \   ___ ___ ___  ___ ___  | |     _ _ __ ___  _| |_ ___ _ __
|  __/ _` / __| __|   / /\ \ / __/ __/ _ \/ __/ __| | |    | | '_ ` _ \| | __/ _ \ '__|
| | | (_| \__ \ |_   / ____ \ (_| (_|  __/\__ \__ \ | |____| | | | | | | | ||  __/ |
|_|  \__,_|___/\__| /_/    \_\___\___\___||___/___/ |______|_|_| |_| |_|_|\__\___|_|

    Author.: Ricardo Abuchaim - ricardoabuchaim@gmail.com
    License: MIT
    Github.: https://github.com/rabuchaim/fastaccesslimiter
    Issues.: https://github.com/rabuchaim/fastaccesslimiter/issues
    PyPI...: https://pypi.org/project/fastaccesslimiter/  ( pip install fastaccesslimiter )

"""
__appname__ = 'FastAccessLimiter'
__version__ = '1.0.0'
__release__ = '10/August/2024'

import os, json, socket, struct, binascii, itertools, time, gzip, threading, functools, bisect, ipaddress
from typing import List, Union
from collections import namedtuple

# import etimedecorator

__all__ = ['FastAccessLimiter']

class FastAccessLimiter:
    def __init__(self,ip_network_list:list=[],with_stats:bool=True,**kwargs):
        """Initializes the Fast Access Limiter object.
        
        Parameters :
        
        - ip_network_list (list): A list of IP network addresses to be used for access limiting. Default is an empty list.
        - with_stats (bool): Flag to enable or disable statistics tracking. Default is True.
        - **kwargs: Additional keyword arguments.
            - debug (bool): Enable or disable debug mode. Default is False.
            - top_hits (int): The maximum number of top hits to be saved in the statistics. Default is 100.
            - cache_size (int): The maximum number of items in the cache. Default is 1024. 0 = no cache.
        """
        self._lock = threading.Lock()
        # enable the debug mode if the environment variable FASTACCESSLIMITER_DEBUG is set OR if the debug parameter is True
        if (os.environ.get("FASTACCESSLIMITER_DEBUG","") != "") or (kwargs.get("debug",False) == True):
            self.__debug = self.__debug_enabled
        # reset the hit counter and the IP statistics dictionary
        self.__hit_counter = itertools.count()
        self.__hit_counter_access = itertools.count()
        self.__stats_ip_dict = {}
        # if with_stats is True, the statistics will be saved, otherwise the statistics will be a null function
        if with_stats:
            self.__stats_save = self.__stats_save_enabled
        # define the maximum number of top hits to be saved in the statistics. Minimum is 1
        self.__top_hits_size = kwargs.get("top_hits",100)
        self.__top_hits_size = 1 if self.__top_hits_size < 0 else self.__top_hits_size
        # define the maximum number of items in the cache. 0 = no cache
        self.__cache_size = kwargs.get("cache_size",1024)
        if self.__cache_size > 0:
            self.__check_iplong_access = functools.lru_cache(maxsize=self.__cache_size)(self.__check_iplong_access)
        # prepare the IP Network list
        self.__ip_network_list, self.__ip_network_list_first_iplong, self.__ip_network_list_last_iplong = self.__prepare_ip_list(ip_network_list)
    ##──── DEBUG MODE ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __debug(self, msg:str):...
    def __debug_enabled(self, msg:str):
        print(f"\033[38;2;0;255;0m[FASTACCESSLIMITER_DEBUG] {str(msg)}\033[0m")
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── IP LIST FUNCTIONS ─────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __prepare_ip_list(self,an_ip_list)->list:
        """Prepare the list of IPs. Remove invalid IPs, convert IPs to CIDR format, remove duplicates, sort the list of IPs in ascending order of IP and remove blank items.
        
        Returns the list of IPs in CIDR format, the list of the first IP of the CIDR and the list of the last IP of the CIDR."""
        start_time = time.monotonic()
        an_ip_list = [self.get_cidr_format(item) for item in an_ip_list if self.ip2int(item.split("/")[0]) != 0]
        # remove invalid CIDRs from the list (ex: 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID)
        new_list = [item for item in an_ip_list if self.is_valid_cidr(item)]
        # sort the list of IPs in ascending order of IP, remove duplicates and blank items
        self.__ip_network_list = new_list = sorted(list(filter(None,sorted(list(dict.fromkeys(new_list))))),key=lambda ip:self.ip2int(ip.split("/")[0]))
        # get the first and last IP of the CIDR and convert them to integer. Keep 2 lists: one with the first IP and another with the last IP
        new_list_first_iplong = [self.ip2int(item.split("/")[0]) for item in new_list]
        new_list_last_iplong = [int(ipaddress.ip_network(item,strict=False)[-1]) for item in new_list]
        # clear the cache of the __check_iplong_access method because the list was changed
        if self.__cache_size > 0:
            self.__check_iplong_access.cache_clear()
        # show the invalid CIDRs if they exist and DEBUG is enabled
        invalid_cidrs = list(set(an_ip_list) - set(new_list))
        if len(invalid_cidrs) > 0:
            self.__debug(f"Invalid CIDRs: {invalid_cidrs}")
        self.__debug(f"Valid ip_netork_list.: {new_list}")
        # self.__debug(f"ip_netork_list_first_iplong: {new_list_first_iplong}")
        # self.__debug(f"ip_netork_list_last_iplong.: {new_list_last_iplong}")
        self.__debug(f"Elapsed time to prepare the IP Network list: {time.monotonic()-start_time:.9f} seconds")
        return new_list, new_list_first_iplong, new_list_last_iplong
    ##───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── IP/CIDR MANIPULATION FUNCTIONS ────────────────────────────────────────────────────────────────────────────────────────────
    @functools.lru_cache(maxsize=1024)
    def ip2int(self,ipaddr:str)->int:
        """Converts an IPv4 or IPv6 address to an integer."""
        try:
            if ipaddr.find(":") < 0:
                return struct.unpack("!L",socket.inet_aton(ipaddr))[0]
            else:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr),byteorder='big')
        except:
            return 0
    @functools.lru_cache(maxsize=1024)
    def is_valid_ip(self,ipaddr:str)->bool:
        """Check if an IPv4 or IPv6 address is valid. Try to convert the IP address to an integer. If it fails, the IP address is invalid. 
        This is the fastest way to check if an IP address is valid, much better than using regular expressions."""
        try:
            if ipaddr.find(":") < 0:
                socket.inet_aton(ipaddr)
            else:
                socket.inet_pton(socket.AF_INET6,ipaddr)
            return True
        except:
            return False
    @functools.lru_cache(maxsize=1024)
    def is_valid_cidr(self,cidr:str)->bool:
        """Check if a CIDR is valid with STRICT MODE. Ex: 
        
        - 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID
        - c1a5:9ba4:8d92:636e:60fd:8756:430b:0000/64 is INVALID, c1a5:9ba4:8d92:636e::/64 is VALID"""
        try: 
            ipaddress.ip_network(cidr,strict=True)
            return True
        except: 
            return False
    @functools.lru_cache(maxsize=1024)
    def get_valid_cidr(self,cidr:str)->Union[str,None]:
        """Convert an invalid CIDR to a valid CIDR. Returns None if the CIDR is completely invalid."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return str(network)
        except ValueError:
            return None
    @functools.lru_cache(maxsize=1024)
    def get_cidr_format(self,ipaddr:str)->str:
        """Converts an IP address to CIDR format. Add /32 to the IPv4 address if it is not present or add /128 to the IPv6 address if it is not present."""
        if (ipaddr.find(":") >= 0 and ipaddr.find("/") < 0):    # IPv6
            return ipaddr+"/128" 
        elif (ipaddr.find(":") < 0 and ipaddr.find("/") < 0):   # IPv4
            return ipaddr+"/32"
        else:
            return ipaddr
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── STATS ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def stats_reset(self)->bool:
        """Reset the hit counter."""
        try:
            with self._lock:
                self.__hit_counter = itertools.count()
                self.__hit_counter_access = itertools.count()
                self.__stats_ip_dict.clear()
            return True
        except:
            return False
    def stats_info(self)->namedtuple:
        """Get the statistics as a namedtuple with the hits and top_hits attribute.
        
        Usage :
        
            access_limiter = FastAccessLimiter(with_stats=True,top_hits=100)
            stats = access_limiter.stats_info()
            print(f"Total hits: {stats.hits}")
            print(f"Top100 IPs: {json.dumps(stats.top_hits,indent=3,sort_keys=False)}")
            
        """
        Stats = namedtuple("Stats", ["hits","top_hits"])
        def int_to_ipv4(iplong):
            return socket.inet_ntoa(struct.pack('>L', iplong))
        def int_to_ipv6(iplong):
            return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(iplong)[2:].zfill(32)))
        return Stats(next(self.__hit_counter)-next(self.__hit_counter_access),
                     {int_to_ipv6(key) if str(key).find(":")>=0 else int_to_ipv4(key):val for key,val in dict(sorted(self.__stats_ip_dict.items(), key=lambda item: item[1], reverse=True)[:self.__top_hits_size]).items()})
    def __stats_save(self,iplong):...
    def __stats_save_enabled(self,iplong):
        next(self.__hit_counter)
        self.__stats_ip_dict[iplong] = self.__stats_ip_dict.get(iplong,0)+1
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── MANAGE IP/CIDR LIST ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def get_ip_network_list(self)->list:
        """Get the list of IPs in the accept list."""
        return self.__ip_network_list
    def add_ip(self,ipaddr_cidr:str)->bool:
        """Add an IP/CIDR to the accept list. 
        
        Returns :
        - True if the IP/CIDR was added to the IP list 
        - False if the IP/CIDR is invalid 
        - None if the IP/CIDR already in the IP list.
        """
        ipaddr_cidr = self.get_cidr_format(ipaddr_cidr)
        if not self.is_valid_cidr(ipaddr_cidr):
            return False
        with self._lock:
            self.__ip_network_list.append(ipaddr_cidr)
            self.__update_ip_list()
        return True
    def remove_ip(self,ipaddr_cidr:str)->bool:
        """Remove an IP/CIDR from the accept list. 
        
        Returns :
        - True if the IP/CIDR was removed from the IP list 
        - False if the IP/CIDR is invalid 
        - None if the IP/CIDR was not in the IP list.
        """
        ipaddr_cidr = self.get_cidr_format(ipaddr_cidr)
        if not self.is_valid_cidr(ipaddr_cidr):
            return False
        with self._lock:
            if ipaddr_cidr in self.__ip_network_list:
                self.__ip_network_list.remove(ipaddr_cidr)
                self.__update_ip_list()
                return True
            return None
    def load_ip_network_list(self,ip_network_list:List[str])->bool:
        """Load a new list of IPs from a variable of type List[str]. Individual IPs will be converted to CIDR /32 format.
        
        Invalid IP/CIDR will be discarded. Use the debug mode (`export FASTACCESSLIMITER_DEBUG=1`) to see the invalid IPs/CIDRs.
        
        Returns :
        - True if the IP list was loaded to the internal IP list 
        - False if the IP list is invalid.
        """
        try:
            with self._lock:
                self.__ip_network_list = ip_network_list
                self.__update_ip_list()
                return True
        except:
            return False
    def extend_ip_network_list(self,ip_network_list:List[str])->bool:
        """Add a list of IPs to the current IP list. Don't worry about duplicates, they will be removed.
        
        Returns :
        - True if the IP list was added to the IP list 
        - False if the IP list is invalid.
        """
        try:
            with self._lock:
                self.__ip_network_list.extend(ip_network_list)
                self.__update_ip_list()
                return True
        except:
            return False
    def save_ip_network_list(self,json_filename:str,gzipped:bool=False,compresslevel:int=9,overwrite_if_exists:bool=True,raise_on_error:bool=False)->bool:
        """Save the list of IPs to a file. 
        
        Parameters :
        - json_filename (str): The name of the file to save the IP list. If the file ends with .gz, it will be considered a gzipped file automatically.
        - gzipped (bool): Flag to save the file in gzipped format. Default is False.
        - compresslevel (int): The compression level of the gzipped file. Default is 9.
        - overwrite_if_exists (bool): Flag to overwrite the file if it already exists. Default is True.
        - raise_on_error (bool): Flag to raise an exception if an error occurs. Default is False.
        
        Returns :
        - True if the IP list was saved to the file 
        - False if the file could not be saved. If raise_on_error is True, an exception will be raised.
        """
        try:
            if gzipped and json_filename[-3:] != ".gz":
                json_filename += ".gz"
            elif json_filename[-3:] == ".gz":
                gzipped = True
            if not overwrite_if_exists and os.path.exists(json_filename):
                if raise_on_error:
                    raise FileExistsError(f"The file {json_filename} already exists.") from None
                return False
            if gzipped:
                with gzip.open(json_filename, "wb",compresslevel=compresslevel) as f:
                    f.write(json.dumps(self.__ip_network_list,sort_keys=False,ensure_ascii=False,separators=(",",":")).encode())
            else:
                with open(json_filename, "w") as f:
                    f.write(json.dumps(self.__ip_network_list,sort_keys=False,ensure_ascii=False,separators=(",",":")))
            return True
        except Exception as ERR:
            if raise_on_error:
                raise ERR from None
            return False
    def open_ip_network_list(self,json_filename:str,raise_on_error:bool=False)->bool:
        """Open the list of IPs from a file. If the file ends with .gz, it will be considered a gzipped file automatically.
        
        Returns :
        - True if the IP list was opened from the file 
        - False if the file could not be opened. If raise_on_error is True, an exception will be raised.
        """
        try:
            if not os.path.exists(json_filename):
                if raise_on_error:
                    raise FileNotFoundError(f"The file {json_filename} does not exist.") from None
                return False
            gzipped = True if json_filename[-3:] == ".gz" else False
            if gzipped:
                with gzip.open(json_filename, "rb") as f:
                    self.__ip_network_list = json.loads(f.read().decode())
            else:
                with open(json_filename, "r") as f:
                    self.__ip_network_list = json.loads(f.read())
            self.__update_ip_list()
            return True
        except Exception as ERR:
            if raise_on_error:
                raise ERR from None
            return False
    def __update_ip_list(self):
        self.__ip_network_list, self.__ip_network_list_first_iplong, self.__ip_network_list_last_iplong = self.__prepare_ip_list(self.__ip_network_list)
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── CHECK IP ACCESS ───────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __check_iplong_access(self,iplong)->bool:
        """Check if the IP address is in the IP/CIDR list.
        
        Returns :
        - The CIDR of the network if the IP is in the IP list
        - False if the IP is not in the IP list OR if the IP list is empty.
        """
        if self.__ip_network_list == []:
            return False
        match_list_index = bisect.bisect_right(self.__ip_network_list_first_iplong, iplong)-1
        try:
            result = (iplong >= self.__ip_network_list_first_iplong[match_list_index]) and (iplong <= self.__ip_network_list_last_iplong[match_list_index])
            if result:
                return self.__ip_network_list[match_list_index] 
            else:
                return False
        except:
            return False
    def __call__(self,ipaddr:str)->bool:
        """Check if the IP address is in the IP/CIDR list.
        
        Returns :
        - The CIDR of the network if the IP is in the IP list
        - False if the IP is not in the IP list OR if the IP list is empty.
        """
        iplong = self.ip2int(ipaddr)
        result = self.__check_iplong_access(iplong)
        if result:
            self.__stats_save(iplong)
        return result
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
