# Ransomware Project

## Introduction
This project involves the development of a ransomware using Python. The ransomware utilizes encryption and a client-server architecture to facilitate data exchange between the attacker and the victim.

## Overview
The main objective of this ransomware is to perform the following tasks:
- Generate a random 128-bit key (16 characters) using ASCII characters.
- Locate all .txt files on the victim's computer and encrypt the content of these files using the generated key.
- Send the encryption key back to the server.
- Infect other systems by sending the compiled malware to a list of emails.

## Requirements
The ransomware includes the following functionalities:

### Payload
- Encrypts all .txt files on the victim's system.
- Utilizes AES (Advanced Encryption Standard) with a chosen encryption mode for encrypting the files, using the randomly generated key.

### Client-Server Communication
- Establishes a client-server connection to facilitate communication between the ransomware and the attacker's server.
- Implements the following server-side functionalities:
  - Generates a public-private key pair using RSA encryption.
  - Accepts a request from the ransomware client to retrieve the public key.
  - Receives the encrypted AES key from the ransomware client and stores it.
  - Decrypts the AES key using the corresponding private key and sends it back to the ransomware client upon request.

### Email Infection
- Compiles a list of target emails to infect other systems.
- Sends the compiled malware to the list of target emails.

## Usage
The ransomware can be executed with the following steps:

### Encryption Phase:
1. Randomly generates a 128-bit key (AES key) using ASCII characters.
2. Locates and encrypts all .txt files on the victim's system using the generated AES key.
3. Sends the encrypted AES key to the attacker's server.

### Email Infection Phase:
1. Compiles a list of target emails to infect.
2. Sends the compiled malware to the target emails.

## Disclaimer
**Note**: This project is for educational purposes only and should not be used maliciously. The usage of ransomware and any unauthorized activities are illegal and strictly prohibited. The project description provided here is for informational purposes only and does not endorse or encourage any illegal activities.
