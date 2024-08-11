# FastAccessLimiter v1.0.0

A fast, lightweight and full-featured IP address access limiter for any Python web framework or even with any application that requires an IP access check. It supports IPv4 and IPv6 simultaneously. It can work with thousands of networks in its block list and has responses in less than 0.000005 seconds (five millionths of a second), which means its use <ins>has no impact on the response time of your API services</ins>. And it's pure Python, zero dependencies!

The blocklist can be dynamically modified at runtime and can even be reset to zero. It accepts any IPv4, IPv6, individual IPs or CIDR networks. Don't worry about invalid IPs, duplicate networks, they are removed automatically. If you export the environment variable `export FASTACCESSLIMITER_DEBUG=1`, you can track whether any invalid IPs/CIDRs have been removed. Simply add the IP or network you want to block and let FastAccessLimiter do the rest.

You can choose to **allow all** and block only the IPs that are included in the `ip_network_list` parameter, or you can work with the reverse logic, and **block all** and allow access only to the IPs that are within the networks included in the `ip_network_list` parameter.

And there is also a statistic that returns the number of positive hits in the checking function and the list of the top 100 IPs that gave hits in this check, along with the count of these occurrences. Statistics can be disabled, and you can modify the size of the Top Hits list.

There are also some useful functions available for manipulating IPs and CIDRs, you can see these functions below in the list of methods.

<!-- If you are looking for a Rate Limiter for your API services, check out [FastRateLimiter](https://pypi.org/project/fastratelimiter/), which is very fast and uses the same methods as FastAccessLimiter. -->

## Installation

```bash
pip install fastacesslimiter
```

## How fast is it?

FastAccessLimiter uses the principle of the [GeoIP2Fast](https://pypi.org/project/geoip2fast/) library to determine if an IP is within a network. It works with network lists converted to integers and only 1 binary search and 1 IF is necessary to know if the IP is within one of the networks in a given list, regardless of its size.

In the test code `test_fastaccesslimiter.py`, we generate a list with 10,000 random class C networks (/24). And we generate 20,000 random IPs, half them belonging to one of those that will be included in the list of blocked networks. Then, 20,000 calls are made to the `FastAccessLimiter` object, counting the time of each one. At the end, an average of these calls is displayed. 

Two tests are performed with the same values, but different object instances, one test printing the results (which is slower) and the other without printing the result.

<img src="https://raw.githubusercontent.com/rabuchaim/fastaccesslimiter/main/images/fastaccesslimiter01.png" width="600">

Below is a snippet of code from the test_fastaccesslimiter.py file.

```python
    (...)
    total_time_list = []
    accessLimiter = FastAccessLimiter(ip_network_list=ip_network_list)  #  <- 10.000 class C networks
    total_start_time = time.monotonic()             #  <- Start time of the test
    for ip in ip_random_list: #  <- 20.000 randomic IPs
        start_time = time.monotonic()               #  <- Start time of each call
        if result := accessLimiter(ip): # The walrus operator (:=) works only in python > 3.8
            end_time = time.monotonic()-start_time  #  <- End time of each call
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[91;1mBLOCKED\033[0m ({result})")
        else:
            end_time = time.monotonic()-start_time  #  <- End time of each call
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[36;1mACCEPTED\033[0m")
    total_end_time = time.monotonic()               #  <- End of the test
    print("\n- Statistics 'printing the results':")
    print(f"Total elapsed time: {total_end_time-total_start_time:.9f}")
    print(f"Total ip_random_list: {len(ip_random_list)} - Total ip_network_list: {len(ip_network_list)}")
    print(f"Average checks per second: {len(total_time_list)/sum(total_time_list):.2f} - "
          f"Average seconds per check: {sum(total_time_list)/len(total_time_list):.9f}")
```
Run the `test_fastaccesslimiter.py` test yourself to see the performance on your machine. Implementing the use of FastAccessLimiter will have no impact on the current response time of your API services.

## Examples

Here are 2 examples with Tornado and FastAPI and only one network in the blocklist, but you can use it with THOUSANDS of networks and the response time will always be less than 0.000005 seconds. 

In the example there is only 1 network, but you can add as many as you want, feel free, don't worry about the number of networks.

You can use this class with any Python web framework or even with any application that requires an IP access check. 

#### Example using Tornado:

```python
from fastaccesslimiter import FastAccessLimiter
import asyncio, tornado

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        if returned_network := accessLimiter(self.request.remote_ip): # The walrus operator (:=) works only in python > 3.8
            self.send_error(403,reason=f"Access denied for network {returned_network}")
        else:
            self.write("Hello, world")

def make_app():
    return tornado.web.Application([(r"/", MainHandler),])

async def main():
    app = make_app()
    app.listen(8888)
    await asyncio.Event().wait()

if __name__ == "__main__":
    accessLimiter = FastAccessLimiter(ip_network_list=['127.0.0.0/8'])
    asyncio.run(main())
```
```bash
# curl http://127.0.0.1:8888/
Access denied for network 127.0.0.0/8
```

By default, the default action **allow all**. If the callback is False, it means that the IP provided in the object call is not equal to or is not within any network specified in the `ip_network_list` parameter.

If the remote IP is within a network specified in the `ip_network_list` parameter, the network belonging to that IP will be returned when the object is called.

If you do not want to get the network that the remote IP matched, you can do it like this:

```python
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        if accessLimiter(self.request.remote_ip):
            self.send_error(403,reason="Access denied")
        else:
            self.write("Hello, world")
```

Obviously, you can reverse the logic and choose to **block all** and allow access only to networks that are included in the `ip_network_list` parameter.

```python
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        if accessLimiter(self.request.remote_ip):
            self.write("Hello, world")
        else:
            self.send_error(403,reason="Access denied")
```

#### Example using FastAPI:

```python 
#!/usr/bin/env python3
from fastaccesslimiter import FastAccessLimiter
from fastapi import FastAPI, Request, HTTPException, status

app = FastAPI()

accessLimiter = FastAccessLimiter(ip_network_list=['127.0.0.0/8'])

@app.get("/")
async def root(request: Request):
    if returned_network := accessLimiter(request.client.host): # The walrus operator (:=) works only in python > 3.8
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for network {returned_network}")
    else:
        return {"Hello": "World"}
```

```bash
# uvicorn test_fastapi:app
INFO:     Started server process [29573]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)

# curl http://127.0.0.1:8000/
{"detail":"Access denied for network 127.0.0.0/8"}
```

As you can see, it is possible to use FastAccessLimiter with any web framework for Python or even with any application that requires an IP access check.


## Methods

- **`__init__(self,ip_network_list:list=[],with_stats:bool=True,**kwargs)`**

    Constructor method for the `FastAccessLimiter` class.

    - `ip_network_list` (list): A list of IP network addresses to be used for access limiting. Default is `[]` (an empty list).
    - `with_stats` (bool): Flag to enable or disable statistics tracking. Default is `True`.
    - `**kwargs`: Additional keyword arguments.
        - `debug` (bool): Enable or disable debug mode. Default is `False`.
        - `top_hits` (int): The maximum number of top hits to be saved in the statistics. Default is `100`.
        - `cache_size` (int): The maximum number of items in the cache. Default is `1024`. 0 = no cache.

    Example:

    ```access_limiter = FastAccessLimiter(ip_network_list=['10.0.0.0/8'],with_stats=True,top_hits=10,cache_size=1024,debug=False)```

    Notes:

    When creating the object and providing a list of IPs, this class will not fix any invalid CIDRs, it will discard them. At most, a /32 or /128 suffix will be added to individual IPs. 

    If you notice that any of the addresses provided are not included in this list after creating the `FastAccessLimiter` object, use the `debug=True` flag to see if they appear in the list of discarded invalid CIDRs. Use the method `get_valid_cidr(cidr:str)` to get the correct CIDR notation if you want to.

#### IP network list manipulation functions:

- **`get_ip_network_list()->List[str]`**

    Method to get the current `ip_network_list` list. This list already returns the CIDRs normalized, validated, without duplications and in ascending IP order.

- **`add_ip(ipaddr_cidr:str)->bool`**

    Method to add an IP Address OR a CIDR to the current `ip_network_list`. Don´t worry about the validation or duplicated values.

- **`remove_ip(ipaddr_cidr:str)->bool`**

    Method to remove an IP Address OR a CIDR from the current `ip_network_list`. Returns `False` if the `ipaddr_cidr` parameter was not found.

- **`load_ip_network_list(ipaddr_cidr:str)->bool`**

    Method to import a new `ip_network_list` after the creation of the object `FastAccessLimiter`. Individual IPs will be converted to CIDR /32 format. Invalid IP/CIDR will be discarded. Use the debug mode (`export FASTACCESSLIMITER_DEBUG=1`) to see the invalid IPs/CIDRs.

- **`extend_ip_network_list(ipaddr_cidr:str)->bool`**

    Method to extend the current `ip_network_list` after the creation of the object `FastAccessLimiter`.

- **`save_ip_network_list(json_filename,gzipped,compresslevel,overwrite_if_exists,raise_on_error)->bool`**

    Method to save the current `ip_network_list` to a json file. Can be compressed also.

    Parameters :
    - `json_filename` (str): The name of the file to save the IP list. If the file ends with .gz, it will be considered a gzipped file automatically.
    - `gzipped` (bool): Flag to save the file in gzipped format. Default is False.
    - `compresslevel` (int): The compression level of the gzipped file. Default is 9.
    - `overwrite_if_exists` (bool): Flag to overwrite the file if it already exists. Default is True.
    - `raise_on_error` (bool): Flag to raise an exception if an error occurs. Default is False.

- **`open_ip_network_list(json_filename,raise_on_error)->bool`**

    Method to open a json file and import it to the `ip_network_list` after the creation of the object `FastAccessLimiter`.

    Parameters :
    - `json_filename` (str): The name of the file to save the IP list. If the file ends with .gz, it will be considered a gzipped file automatically.
    - `raise_on_error` (bool): Flag to raise an exception if an error occurs. Default is False.

#### Statistics functions:

- **`stats_info()->namedtuple("Stats", ["hits","top_hits"])`**

    Method to return a named tuple with the `hits` and `top_hits` attribute.

    Usage :
    ```python
        access_limiter = FastAccessLimiter(with_stats=True,top_hits=10)
        stats = access_limiter.stats_info()
        print(f"Total hits: {stats.hits}")
        print(f"Top100 IPs: {json.dumps(stats.top_hits,indent=3,sort_keys=False)}")
    ```
    Returns something like:
    ```
    Stats(hits=10004, top_hits={'56.173.220.87': 115, '104.68.3.230': 94, '1.50.7.106': 88, '38.253.253.12': 74, '82.178.232.186': 66, '138.82.25.126': 50, '35.159.124.212': 43, '62.180.136.46': 33, '69.24.228.90': 21, '207.67.178.173': 18})
    ```

- **`stats_reset()->bool`**

    Method to reset all the statistics information.

#### Extra IP/CIDR manipulation functions:

- **`ip2int(ipaddr)->int`**

    Method to return and IP address to the integer format. Can be an IPv4 or IPv6. Returns 0 if the given `ipaddr` is invalid.

- **`is_valid_ip(ipaddr)->bool`**

    Method to return True if the given `ipaddr` is valid. Try to convert the IP address to an integer. If it fails, the IP address is invalid. This is the fastest way to check if an IP address is valid, much better than using regular expressions.

- **`is_valid_cidr(cidr)->bool`**

    Method to return True if the given `cidr` is valid.

    Notes:
    - 10.0.0.10/8 is INVALID, 10.0.0.0/8 is VALID, 10.0.0.10/32 is VALID
    - c1a5:9ba4:8d92:636e:60fd:8756:430b:0000/64 is INVALID, c1a5:9ba4:8d92:636e::/64 is VALID"""

- **`get_valid_cidr(cidr)->Union[str,None]`**

    Method to return the valid cidr from a given `cidr`. If the given `cidr` is INVALID, returns None.

    Example:
    - get_valid_cidr('10.0.0.10/8') returns `10.0.0.0/8`
    - get_valid_cidr('10.0.0.10') returns `10.0.0.0/32`
    - get_valid_cidr('a.b.c.d') returns: `None`

- **`get_cidr_format(cidr)->str`**

    Method to return the cidr notation from a given `cidr`. Unlike the previous function, this function does not change the value provided in the `cidr` parameter, it only adds /32 (IPv4) or /128 (IPv6) if a suffix is missing.


## Sugestions, feedbacks, bugs...

Open an [issue](https://github.com/rabuchaim/fastaccesslimiter/issues) or e-mail me ricardoabuchaim at gmail.com
