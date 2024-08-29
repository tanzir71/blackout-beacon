The script takes input from a file called ip_list.txt and generates an output file called active_ips.txt.

Depending on how many IP addresses you enter in the **ip_list.txt** file will impact the time required for the script to generate the output file. In desperate times, you can simply keep it running while you are away. For those who are hosting, you can keep your device online for longer to ensure your IP address doesn’t change.

- The **ip_list.txt** file counts each new line as a new entry.
- You can define IP ranges with a hyphen like so: 192.168.0.0-192.168.255.255
    - You can also define single IP addresses such as: 192.168.68.105
    - Such a long-range can take forever to run. Hence, it’s better to make some educated guesses using the Command Prompt method I described above.
- IP addresses that fall within this range are private (meaning, only available to users in your ISP’s network):
    - 10.0.0.0 to 10.255.255.255
    - 172.16.0.0 to 172.31.255.255
    - 192.168.0.0 to 192.168.255.255
- IP addresses outside the above range can be accessed nationwide, and they are likely static. Meaning, once you find a website with a static IP, that address is likely to work in the future as well, given the machine is online (i.e. turned on).
