# WifiCut - Work in progress

## Description

**WifiCut** is a Python program designed for macOS users to manage and control network connectivity on their local network. The program leverages ARP spoofing techniques to restrict and unrestrict the connectivity of devices within the network. It provides a web-based interface using Flask, allowing users to interact with the tool through a user-friendly interface.

### Key Features:

- **ARP Spoofing:** The program utilizes ARP spoofing to manipulate network traffic, enabling the restriction and unrestriction of device connectivity.

- **Web Interface:** A Flask web application provides an intuitive interface for users to manage network connectivity.

- **Dynamic Device Detection:** The tool uses Nmap to dynamically detect and display devices within the local network, making it easy for users to select devices for connectivity control.

### Prerequisites

- Python 3
- macOS operating system
- Required Python packages (install using `pip install -r requirements.txt`)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/manucepeda/WifiCut.git
   cd WifiCut
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the program:
   ```bash
   sudo python3 ./wificutmain.py
   ```

4. Open a web browser and navigate to [http://127.0.0.1:8090/](http://127.0.0.1:8090/) to access the web interface.

### Usage

1. Access the web interface by visiting [http://127.0.0.1:8090/](http://127.0.0.1:8090/) in your web browser.

2. The tool dynamically detects devices on the local network using Nmap. Select a device from the list to control its connectivity.

3. Choose the "Restrict" or "Unrestrict" option to control the connectivity of the selected device.

### Important Notes

- Ensure that you have the necessary permissions to run the program and manipulate network settings.

- Use this tool responsibly and only on networks that you own or have explicit permission to manage.

## Disclaimer

**Recreational and Educational Use Only**

The Network Connectivity Control Tool is developed and provided for recreational and educational purposes. It is intended to be used in controlled environments by individuals with proper authorization or explicit consent from network owners. The tool should not be employed for malicious activities, unauthorized network manipulation, or any action that may infringe on the privacy and rights of others.

### Acknowledgments

This program uses various Python libraries, including Flask, Scapy, and Nmap. 

### License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.

