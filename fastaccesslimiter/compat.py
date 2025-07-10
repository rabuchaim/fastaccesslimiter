from .fastaccesslimiter import FastAccessLimiter as FastAccessLimiterV2
import warnings, typing

class FastAccessLimiter(FastAccessLimiterV2):
    def extend_ip_network_list(self, ip_networks_list: typing.List[str]) -> None:
        if not self.__ignore_warnings:
            warnings.warn("extend_ip_network_list is deprecated. Use add_ip_networks_list instead.",DeprecationWarning,stacklevel=2)
        FastAccessLimiterV2.add_ip_networks_list(self, ip_networks_list)
        
    def add_ip(self, ip: str) -> None:
        if not self.__ignore_warnings:
            warnings.warn("add_ip is deprecated. Use add_ip_network instead.",DeprecationWarning,stacklevel=2)
        FastAccessLimiterV2.add_ip_network(self, ip)
        
    def remove_ip(self, ip: str) -> None:
        if not self.__ignore_warnings:
            warnings.warn("remove_ip is deprecated. Use remove_ip_network instead.",DeprecationWarning,stacklevel=2)
        return FastAccessLimiterV2.remove_ip_network(self, ip)
        
    def get_ip_network_list(self) -> typing.List[str]:
        if not self.__ignore_warnings:
            warnings.warn("get_ip_network_list is deprecated. Use get_ip_networks instead.",DeprecationWarning,stacklevel=2)
        return FastAccessLimiterV2.get_ip_networks_list(self)

    def get_cidr_format(self,ipaddr:str)->str:
        if not self.__ignore_warnings:
            warnings.warn("get_cidr_format is deprecated. Use _normalize_cidr_suffix instead.",DeprecationWarning,stacklevel=2)
        return FastAccessLimiterV2._normalize_cidr_suffix(ipaddr)

    def is_valid_ip(self, ip: str) -> bool:
        if not self.__ignore_warnings:
            warnings.warn("is_valid_ip is deprecated. Use is_valid_ipaddr instead.",DeprecationWarning,stacklevel=2)
        return FastAccessLimiterV2.is_valid_ipaddr(self, ip)
    
    def ip2int(self, ip: str) -> int:
        if not self.__ignore_warnings:
            warnings.warn("ip2int is deprecated. Use ip_to_int instead.",DeprecationWarning,stacklevel=2)
        return FastAccessLimiterV2.ip_to_int(ip)
    
    def save_ip_network_list(self, filename: str) -> None:
        if not self.__ignore_warnings:
            warnings.warn("save_ip_network_list is deprecated. Use save_ip_networks_list instead.",DeprecationWarning,stacklevel=2)
        FastAccessLimiterV2.save_ip_networks_list(self, filename)
        
    def load_ip_network_list(self, ip_networks_list: typing.List[str]) -> None:
        if not self.__ignore_warnings:
            warnings.warn("load_ip_network_list is deprecated. Use set_ip_networks_list instead.",DeprecationWarning,stacklevel=2)
        FastAccessLimiterV2.set_ip_networks_list(self, ip_networks_list)
        
    def open_ip_network_list(self, filename: str) -> None:
        if not self.__ignore_warnings:
            warnings.warn("open_ip_network_list is deprecated. Use open_ip_networks_list instead.",DeprecationWarning,stacklevel=2)
        FastAccessLimiterV2.open_ip_networks_list(self, filename)
    
    