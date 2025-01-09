# Port Scanner

## Functionality

Input: Subnet and netmask

Output: Open IP's and open ports

Uses multi-threading to optimize the script

## Theory

SYN Scan
1. Send SYN to targer
2a. No response (port closed)
2b. SYN/ACK (port open)
3. Omit final ACK packet