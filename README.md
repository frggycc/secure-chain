# Secure Supply Management Project

## Overview
This project propose the design and implementation of a secure supply chain management that offers
**authenticity**, **confidentuality**, and **integrity** in communicating over a netwrok using TLS,
AES encryption, and bycrypt for password hashing. The main focus is on a server-clinet communication model where certificates and encryption ensure secure transactions. 

While this project is not ready for a real-world deployment, it demostrates several key techniques
and functionalities that can establish secure commucation channels.

##Prerequisties

Before running this program, make sure you have the following configured:
1. Python3
2. Pip
3. Bycrypt

Install Python3 directions:

  pyhton3 --version //Check if you have installed already, if so you can skip installation
  sudo apt-get update
  sudo apt-get install python3.6

Installing pip:

  sudo apt install python3-pip

Installing bycrypt:

  sudo apt-get install bycrypt

## Clone and set up the Repository

1. Clone the repository
  git clone https://github.com/frggycc/secure-chain
  cd secure-chain

## Running the server and Client
1. Start the server
cd secure-chain
python3 server.py

2. Run the client

python3 client.py <SERVER_IP> <PORT> <AES_KEY>

3. Log in or Create a New account

