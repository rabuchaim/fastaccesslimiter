#!/usr/bin/env python3

import sys, socket, struct, random, time, datetime as dt
from fastaccesslimiter import FastAccessLimiter

def randomipv4():
    return socket.inet_ntoa(struct.pack('>L',random.randint(16777216,3758096383)))

def randomipv6():
    return ':'.join([f'{random.randint(0, 0xffff):04x}' for _ in range(8)])

# ip_list.extend([randomipv6() for i in range(10000)])
# ip_list.extend(['1.1.1.1','2.2.2.2','3.3.3.3','4.4.4.4','5.5.5.5','6.6.6.6','7.7.7.7','8.8.8.8','9.9.9.9','10.10.10.10'])

if __name__ == "__main__":
    ip_network_list, ip_random_list = [], []
    # creates a list with 20000 random ipv4 addresses
    ip_random_list.extend([randomipv4() for i in range(20000)])
    # creates a list with 10000 random ipv4 network addresses
    for ip in ip_random_list[-10000:]:
        octet = ip.split('.')
        ip_network_list.append(f'{octet[0]}.{octet[1]}.{octet[2]}.0/24')
    # shuffle the lists    
    random.shuffle(ip_random_list)        
    random.shuffle(ip_network_list)
    # Countdown to start the tests
    print("")
    for I in range(5):
        countdown = 5-I
        print(f"\r>>> Starting tests for FastAcessLimiter in {countdown} seconds...",end="")
        sys.stdout.flush()
        # time.sleep(1)
    print("\n")
    # Starting the tests PRINTING THE RESULTS (spent more time)
    total_time_list = []
    accessLimiter = FastAccessLimiter(ip_network_list=ip_network_list)
    total_start_time = time.monotonic()
    for ip in ip_random_list:
        start_time = time.monotonic()
        if result := accessLimiter(ip):
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[91;1mBLOCKED\033[0m ({result})")
            pass
        else:
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            print(f"[{end_time:.9f}] IP {ip} is \033[36;1mACCEPTED\033[0m")
            pass
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
    accessLimiter = FastAccessLimiter(ip_network_list=ip_network_list,top_hits=10)
    total_start_time = time.monotonic()
    for ip in ip_random_list:
        start_time = time.monotonic()
        if result := accessLimiter(ip):
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            # Return your error message here
        else:
            end_time = time.monotonic()-start_time
            total_time_list.append(end_time)
            # Your API code starts here
    print("")
    print("- Statistics 'without print the results':")
    total_end_time = time.monotonic()
    print(f"Total elapsed time: {total_end_time-total_start_time:.9f}")
    print(f"Total ip_random_list: {len(ip_random_list)} - Total ip_network_list: {len(ip_network_list)}")
    print(f"Average checks per second: {len(total_time_list)/sum(total_time_list):.2f} - "
          f"Average seconds per check: {sum(total_time_list)/len(total_time_list):.9f}")
    print(accessLimiter.stats_info())
    print("")
    