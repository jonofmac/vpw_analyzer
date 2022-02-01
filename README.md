# VPW Analyzer
A visual J1850 VPW analyzer written in Python

Requires Tkinter, Pandas, serial, and Python3
These can be installed with pip or a package manager.
```
pip3 install tk pandas serial
```

Running the program is as simple as pointing the python3 executable to the vpw_analyzer.py file with 
```
python3 vpw_analyzer.py
```
# How to use
Any ELM327 device should be compatible with this, as it uses only basic AT commands to listen to the bus. 

You need to enter the serial port into the "OBD Device Serial Port" box. For Windows, this is typically a "COM1" name. Check device manager to get the actual COM port.
For Linux, you need to specify the full /dev/tty device path. 
Once the serial device is entered, press the "Read" button to connect and begin listening to the bus.

There are 2 boxes in main window. The bottom box shows the messages that were received in order. The top box shows unique messages. For example, if duplicate messages are received, then you would see it twice in the bottom box, but only once in the top box. By changing the "Compare First # Bytes" dropdown changes how many bytes of a data payload are compared to determine if a message is unique or not. Most data responses contain 2 bytes that are an acknowledgement and an ID confirmation.

To export a log to a text file, click the "Export Logs" button.
To import a log (or any text file with 1 message per line), enter the path (relative to vpw_analyzer.py or absolute both work) to the text file into the OBD Device Serial Port box and press "Read" button.

Clear Message Logs button will clear out the messages.

# Known Issues
- Sending messages does not work

