# Data Communication Error Detection Simulator

This project is a simple simulation of data transmission between a **Sender**, a **Server**, and a **Receiver** using Python and Tkinter.  
It demonstrates how different **error detection techniques** can detect corrupted data in a network.

## 🧩 Components

- **Sender** – User enters a message, selects an error detection method, and sends it.
- **Server** – Receives the packet, randomly injects errors into the data, and forwards it.
- **Receiver** – Recomputes control bits and decides if the received data is **CORRECT** or **CORRUPTED**.

## 🔍 Error Detection Methods

Implemented methods include:

- Parity Bit  
- 2D Parity  
- CRC-16 (CCITT)  
- Hamming (12,8)  
- Internet Checksum  

## ▶️ How to Run

1. Start **Receiver**:
   ```bash
   python receiver.py
