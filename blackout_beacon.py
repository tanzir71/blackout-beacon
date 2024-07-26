import ipaddress
import socket
import time
import os

def check_ip(ip):
  try:
    socket.gethostbyaddr(ip)
    return True
  except socket.error:
    return False

def process_ip_range(ip_range):
  start_ip, end_ip = ip_range.split('-')
  start_ip = int(ipaddress.ip_address(start_ip))
  end_ip = int(ipaddress.ip_address(end_ip))
  ip_list = [str(ipaddress.ip_address(ip)) for ip in range(start_ip, end_ip + 1)]
  return ip_list

def main():
  # Replace 'ip_list.txt' with the desired file path
  # input_file = 'ip_list.txt'  # Relative path

  here = os.path.dirname(os.path.abspath(__file__))

  input_file = os.path.join(here, 'ip_list.txt')

  output_file = os.path.join(here, 'active_ips.txt')

  try:
    with open(input_file, 'r') as f:
      ip_addresses = f.read().splitlines()

    active_ips = []
    for ip in ip_addresses:
      if '-' in ip:
        ip_list = process_ip_range(ip)
        for single_ip in ip_list:
          if check_ip(single_ip):
            active_ips.append(single_ip)
      else:
        if check_ip(ip):
          active_ips.append(ip)

    if active_ips:
      with open(output_file, 'w') as f:
        f.write('\n'.join(active_ips))
      print("Active IP addresses written to", output_file)
    else:
      print("No active IP addresses found.")

  except FileNotFoundError:
    print("Input file not found:", input_file)

if __name__ == '__main__':
  main()