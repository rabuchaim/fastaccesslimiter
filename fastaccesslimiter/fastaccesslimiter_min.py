#!/usr/bin/env python3
"""FastAccessLimiter Minimal v1.0.0 - A minified version of FastAccessLimiter for Python."""
import os,json,socket,struct,binascii,itertools,time,gzip,threading,functools,bisect,ipaddress,typing,collections
class FastAccessLimiter:
	def __init__(self,ip_network_list=[],with_stats=True,**kwargs):
		self._lock=threading.Lock()
		if os.environ.get('FASTACCESSLIMITER_DEBUG','')!=''or kwargs.get('debug',False)==True:self.__debug=self.__debug_enabled
		self.__hit_counter=itertools.count();self.__hit_counter_access=itertools.count();self.__stats_ip_dict={}
		if with_stats:self.__stats_save=self.__stats_save_enabled
		self.__top_hits_size=kwargs.get('top_hits',100);self.__top_hits_size=1 if self.__top_hits_size<0 else self.__top_hits_size;self.__cache_size=kwargs.get('cache_size',1024)
		if self.__cache_size>0:self.__check_iplong_access=functools.lru_cache(maxsize=self.__cache_size)(self.__check_iplong_access)
		self.__ip_network_list,self.__ip_network_list_first_iplong,self.__ip_network_list_last_iplong=self.__prepare_ip_list(ip_network_list)
	def __debug(self,msg):...
	def __debug_enabled(self,msg):print(f"[38;2;0;255;0m[FASTACCESSLIMITER_DEBUG] {str(msg)}[0m")
	def __prepare_ip_list(self,an_ip_list):
		start_time=time.monotonic();an_ip_list=[self.get_cidr_format(item)for item in an_ip_list if self.ip2int(item.split('/')[0])!=0];new_list=[item for item in an_ip_list if self.is_valid_cidr(item)];self.__ip_network_list=new_list=sorted(list(filter(None,sorted(list(dict.fromkeys(new_list))))),key=lambda ip:self.ip2int(ip.split('/')[0]));new_list_first_iplong=[self.ip2int(item.split('/')[0])for item in new_list];new_list_last_iplong=[int(ipaddress.ip_network(item,strict=False)[-1])for item in new_list]
		if self.__cache_size>0:self.__check_iplong_access.cache_clear()
		invalid_cidrs=list(set(an_ip_list)-set(new_list))
		if len(invalid_cidrs)>0:self.__debug(f"Invalid CIDRs: {invalid_cidrs}")
		self.__debug(f"Valid ip_netork_list.: {new_list}");self.__debug(f"Elapsed time to prepare the IP Network list: {time.monotonic()-start_time:.9f} seconds");return new_list,new_list_first_iplong,new_list_last_iplong
	@functools.lru_cache(maxsize=1024)
	def ip2int(self,ipaddr):
		try:
			if ipaddr.find(':')<0:return struct.unpack('!L',socket.inet_aton(ipaddr))[0]
			else:return int.from_bytes(socket.inet_pton(socket.AF_INET6,ipaddr),byteorder='big')
		except:return 0
	@functools.lru_cache(maxsize=1024)
	def is_valid_ip(self,ipaddr):
		try:
			if ipaddr.find(':')<0:socket.inet_aton(ipaddr)
			else:socket.inet_pton(socket.AF_INET6,ipaddr)
			return True
		except:return False
	@functools.lru_cache(maxsize=1024)
	def is_valid_cidr(self,cidr):
		try:ipaddress.ip_network(cidr,strict=True);return True
		except:return False
	@functools.lru_cache(maxsize=1024)
	def get_valid_cidr(self,cidr)->typing.Union[str,None]:
		try:network=ipaddress.ip_network(cidr,strict=False);return str(network)
		except ValueError:return None
	@functools.lru_cache(maxsize=1024)
	def get_cidr_format(self,ipaddr):
		if ipaddr.find(':')>=0 and ipaddr.find('/')<0:return ipaddr+'/128'
		elif ipaddr.find(':')<0 and ipaddr.find('/')<0:return ipaddr+'/32'
		else:return ipaddr
	def stats_reset(self):
		try:
			with self._lock:self.__hit_counter=itertools.count();self.__hit_counter_access=itertools.count();self.__stats_ip_dict.clear()
			return True
		except:return False
	def stats_info(self):
		Stats=collections.namedtuple('Stats',['hits','top_hits'])
		def int_to_ipv4(iplong):return socket.inet_ntoa(struct.pack('>L',iplong))
		def int_to_ipv6(iplong):return socket.inet_ntop(socket.AF_INET6,binascii.unhexlify(hex(iplong)[2:].zfill(32)))
		return Stats(next(self.__hit_counter)-next(self.__hit_counter_access),{int_to_ipv6(key)if str(key).find(':')>=0 else int_to_ipv4(key):val for(key,val)in dict(sorted(self.__stats_ip_dict.items(),key=lambda item:item[1],reverse=True)[:self.__top_hits_size]).items()})
	def __stats_save(self,iplong):...
	def __stats_save_enabled(self,iplong):next(self.__hit_counter);self.__stats_ip_dict[iplong]=self.__stats_ip_dict.get(iplong,0)+1
	def get_ip_network_list(self):return self.__ip_network_list
	def add_ip(self,ipaddr_cidr):
		ipaddr_cidr=self.get_cidr_format(ipaddr_cidr)
		if not self.is_valid_cidr(ipaddr_cidr):return False
		with self._lock:self.__ip_network_list.append(ipaddr_cidr);self.__update_ip_list()
		return True
	def remove_ip(self,ipaddr_cidr):
		ipaddr_cidr=self.get_cidr_format(ipaddr_cidr)
		if not self.is_valid_cidr(ipaddr_cidr):return False
		with self._lock:
			if ipaddr_cidr in self.__ip_network_list:self.__ip_network_list.remove(ipaddr_cidr);self.__update_ip_list();return True
			return None
	def load_ip_network_list(self,ip_network_list):
		try:
			with self._lock:self.__ip_network_list=ip_network_list;self.__update_ip_list();return True
		except:return False
	def extend_ip_network_list(self,ip_network_list):
		try:
			with self._lock:self.__ip_network_list.extend(ip_network_list);self.__update_ip_list();return True
		except:return False
	def save_ip_network_list(self,json_filename,gzipped=False,compresslevel=9,overwrite_if_exists=True,raise_on_error=False):
		try:
			if gzipped and json_filename[-3:]!='.gz':json_filename+='.gz'
			elif json_filename[-3:]=='.gz':gzipped=True
			if not overwrite_if_exists and os.path.exists(json_filename):
				if raise_on_error:raise FileExistsError(f"The file {json_filename} already exists.")from None
				return False
			if gzipped:
				with gzip.open(json_filename,'wb',compresslevel=compresslevel)as f:f.write(json.dumps(self.__ip_network_list,sort_keys=False,ensure_ascii=False,separators=(',',':')).encode())
			else:
				with open(json_filename,'w')as f:f.write(json.dumps(self.__ip_network_list,sort_keys=False,ensure_ascii=False,separators=(',',':')))
			return True
		except Exception as ERR:
			if raise_on_error:raise ERR from None
			return False
	def open_ip_network_list(self,json_filename,raise_on_error=False):
		try:
			if not os.path.exists(json_filename):
				if raise_on_error:raise FileNotFoundError(f"The file {json_filename} does not exist.")from None
				return False
			gzipped=True if json_filename[-3:]=='.gz'else False
			if gzipped:
				with gzip.open(json_filename,'rb')as f:self.__ip_network_list=json.loads(f.read().decode())
			else:
				with open(json_filename,'r')as f:self.__ip_network_list=json.loads(f.read())
			self.__update_ip_list();return True
		except Exception as ERR:
			if raise_on_error:raise ERR from None
			return False
	def __update_ip_list(self):self.__ip_network_list,self.__ip_network_list_first_iplong,self.__ip_network_list_last_iplong=self.__prepare_ip_list(self.__ip_network_list)
	def __check_iplong_access(self,iplong):
		if self.__ip_network_list==[]:return False
		match_list_index=bisect.bisect_right(self.__ip_network_list_first_iplong,iplong)-1
		try:
			result=iplong>=self.__ip_network_list_first_iplong[match_list_index]and iplong<=self.__ip_network_list_last_iplong[match_list_index]
			if result:return self.__ip_network_list[match_list_index]
			else:return False
		except:return False
	def __call__(self,ipaddr):
		iplong=self.ip2int(ipaddr);result=self.__check_iplong_access(iplong)
		if result:self.__stats_save(iplong)
		return result