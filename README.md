# Custom ARP Packet Generator with Scapy
## Overview
This project provides a Python script that generates customized ARP (Address Resolution Protocol) packets using the Scapy library. The program allows you to modify ARP packets to manipulate the ARP tables of the router and target devices. This project is intended for educational purposes only and emphasizes the importance of using technology responsibly.

## Packet Injection and Scapy
### Packet Injection
Packet injection is a technique used to create and send custom network packets directly onto a network interface. In this project, we leverage the Scapy library to achieve packet injection, enabling us to craft and send ARP packets tailored to our specific requirements.

### Scapy
Scapy is a powerful Python library for network packet manipulation. It provides a high-level interface to construct and manipulate network packets at different layers, making it an ideal tool for crafting custom ARP packets.

### Usage
To use this script, follow these steps:

1. Install Scapy if you haven't already. You can install it using pip:

    ```shell 
    pip install scapy
2. Clone the repository to your local machine:
    ```shell 
    git clone https://github.com/alclev/arp_poisoning.git 

3. Navigate to the project directory:
    ```shell 
    cd arp_poisoning

Modify the Python script (custom_arp_generator.py) to customize the ARP packets as per your requirements. You can specify the source and destination IP addresses, MAC addresses, and other ARP packet fields.

4. Run the script:
    ```shell
    python main.py

The script will construct and send the customized ARP packets onto the network interface, allowing you to manipulate the ARP tables of the router and target devices.

## Ethics and Responsible Use
### Educational Purposes
This project is intended solely for educational purposes to help individuals learn about network protocols, ARP, and packet manipulation using the Scapy library. It should not be used for malicious activities, unauthorized network intrusion, or any activities that violate ethical and legal standards.

### Responsible Use of Technology
Responsible use of technology is essential. When using this tool, it's crucial to consider the ethical implications and adhere to legal and ethical guidelines. Misuse of such technology can have serious legal consequences and can harm network integrity and security.

### Disclaimer
This project and its authors are not responsible for any misuse or illegal activities conducted with this tool. Use it responsibly, respect the privacy and security of others, and comply with all applicable laws and regulations.

### Contributing
Contributions to this project are welcome. If you have suggestions, improvements, or bug fixes, please submit a pull request.