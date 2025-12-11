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

1. Sender**
- User enters a message.
- Selects an error detection method.
- Application generates the corresponding control bits (CRC, Hamming, Parity, etc.).
- Sends a packet in the format:
_____________________________________
2. Server**
- Receives clean packet from Sender.
- Randomly applies an **error injection method**:
- Bit Flip  
- Character Deletion  
- Random Insertion  
- Burst Error  
- Forwards the CORRUPTED data (but keeps the original control bits) to the Receiver.
_________________________________________________
3. Receiver**
- Receives the corrupted/clean packet.
- Recomputes the control bits.
- Compares:
