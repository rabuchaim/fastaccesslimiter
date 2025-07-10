#!/usr/bin/env python3

import socket, struct, random, time
# from fastaccesslimiter.compat import FastAccessLimiter
# from fastaccesslimiter.fastaccesslimiter_min import FastAccessLimiter
from fastaccesslimiter import FastAccessLimiter

def randomipv4():
    return socket.inet_ntoa(struct.pack('>L',random.randint(16777216,3758096383)))

def randomipv6():
    return ':'.join([f'{random.randint(0, 0xffff):04x}' for _ in range(8)])

# ip_list = []
# ip_list.extend(['1.1.1.1','2.2.2.2','3.3.3.3','4.4.4.4','5.5.5.5','6.6.6.6','7.7.7.7','8.8.8.8','9.9.9.9','10.10.10.10'])
# ip_list.extend([randomipv6() for i in range(10000)])

# if __name__ == "__main__":
#     print("FastAccessLimiter Test")
#     ip_network_list = ['1.1.2.1/24','a.v.s.d','100.200.300.100','0','1',2,'134744072/24']
#     ip_random_list = ['1.1.1.1','1.1.2.10']
#     limiter = FastAccessLimiter(ip_networks_list=ip_network_list,debug=True)
#     print(f"IP Network List: {limiter.get_ip_networks_list()}")
#     quit()

if __name__ == "__main__":
    ip_network_list, ip_random_list = [], []
    # creates a list with 40000 random ipv4 and ipv6 addresses
    ip_random_list.extend([randomipv4() for i in range(20000)])
    ip_random_list.extend([randomipv6() for i in range(20000)])
    random.shuffle(ip_random_list)        
    # creates a list with 20000 random ipv4 network addresses
    for ip in ip_random_list[-20000:]:
        if '.' in ip:
            octet = ip.split('.')
            ip_network_list.append(f'{octet[0]}.{octet[1]}.{octet[2]}.0/24')
        else:
            # For IPv6, we will use a /64 prefix for simplicity
            ip_network_list.append(f'{ip}/64')
    # shuffle the lists    
    random.shuffle(ip_random_list)        
    random.shuffle(ip_network_list)
    print("")
    # Countdown to start the tests
    # for I in range(5):
    #     countdown = 5-I
    #     print(f"\r>>> Starting tests for FastAcessLimiter in {countdown} seconds...",end="")
    #     sys.stdout.flush()
    #     time.sleep(1)
    # print("\n")
    # Starting the tests PRINTING THE RESULTS (spent more time)
    total_time_list = []
    accessLimiter = FastAccessLimiter(ip_network_list=ip_network_list,normalize_invalid_cidr=True,debug=False)
    total_start_time = time.monotonic()
    for ip in ip_random_list:
        start_time = time.monotonic()
        result = accessLimiter(ip)
        if result:
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[36;1mACCEPTED\033[0m (Network: {result})")
        else:
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[91;1mBLOCKED\033[0m")
    # Print the statistics for the test with print the results
    print("")
    print("- Statistics 'printing the results':")
    total_end_time = time.monotonic()
    print(f"Total elapsed time: {total_end_time-total_start_time:.9f}")
    print(f"Total ip_random_list: {len(ip_random_list)} - Total ip_network_list: {len(ip_network_list)}")
    print(f"Average checks per second: {len(total_time_list)/sum(total_time_list):.2f} - "
          f"Average seconds per check: {sum(total_time_list)/len(total_time_list):.9f}")
    print("")

    # Starting the tests WITHOUT PRINTING THE RESULTS (spent less time, more faster)
    print("- "*40)
    print("  Starting a new test without print the results:")
    print("- "*40)
    # shuffle the lists again
    random.shuffle(ip_random_list)        
    random.shuffle(ip_network_list)        
    # Reset the total_time_list
    total_time_list.clear()
    # Create a new instance of FastAccessLimiter
    accessLimiter = FastAccessLimiter(ip_network_list=ip_network_list,normalize_invalid_cidr=True,top_hits=20,with_stats=True)
    total_start_time = time.monotonic()
    for i in range(10):
        for ip in ip_random_list:
            go_no_go = random.randint(0, 10)
            if go_no_go > 0:  # 10% chance to check the IP
                continue
            start_time = time.monotonic()
            result = accessLimiter(ip)
            if result:
                end_time = time.monotonic()-start_time
                total_time_list.append(end_time)
                # Your API code starts here
            else:
                end_time = time.monotonic()-start_time
                total_time_list.append(end_time)
                # Return your error message here
    print("")
    print("- Statistics 'without print the results':")
    total_end_time = time.monotonic()
    print(f"Total elapsed time: {total_end_time-total_start_time:.9f}")
    print(f"Total ip_random_list: {len(ip_random_list)} - Total ip_network_list: {len(ip_network_list)}")
    print(f"Average checks per second: {len(total_time_list)/sum(total_time_list):.2f} - "
          f"Average seconds per check: {sum(total_time_list)/len(total_time_list):.9f}")
    print("")
    print(f"Hits: {accessLimiter.stats_info().hits}" )
    print(f"Top Hits IP List: {accessLimiter.stats_info().top_hits}" )
    print("")
    