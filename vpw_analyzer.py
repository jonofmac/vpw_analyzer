'''
VPW Analyzer
By Jonathan Valdez

Version 0.3 - Feb 1, 2022
Description: This is a utility that parses incoming messages from a VPW interface
    into a more human-readable format. The bottom box shows each message that was
    received in order. The top box shows unique messages that were received.
    It connects to an ELM327 like device via a serial port. If on Windows, type
    the COM port number into the 'OBD Device Port' and press 'Read'. If on Unix
    based system, type in the full path (/dev/serialTTY) and press 'Read'.

Changes
    - TBD


Version 0.2 - Jan 26, 2022
Changes
    - Fixed crashing on exit
    - Added some device response verification steps
    - Query device string to get model and firmware info
'''
from logging import exception
import tkinter as tk
from tkinter import messagebox, filedialog
import tkinter.ttk as ttk
import binascii
import queue
import threading
import time
import pandas as pd
import string
import serial
import sys
import re

'''
OBD class is used to communicate
'''
class OBD():
    def __init__(self, filename):
        self.filename = filename
        self.fd = None
        self.sp = None
        self.lines = None
        self.serial = False
        self.dev_ati_string = None
        self.dev_sti_string = None
        self.dev_dxi_string = None
        self.dev_type = None
        self.dev_string = None
        
        # There is probably a better way to determine if something is a serial device or not.
        if ("/dev" in filename or "COM" in filename or "com" in filename):
            self.serial = True
        

    def __del__ (self):
        self.close()
        
    def open(self):
    
        if (self.serial):
            print ("Opening serial port:", self.filename)
        else:
            print ("Opening file:", self.filename)


        if (self.serial):
            if self.sp:
                self.sp.close()

            self.sp = serial.Serial(timeout=3)
            self.sp.port = self.filename
            self.sp.open()
            
            if (self.sp.is_open == False):
                raise Exception("Unable to open serial port")
                
            
            # Configure the modem
            self.sp.write(b'\r')        # Wake the part
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("No data received. Not connected/wrong serial port?")
            self.sp.write(b'atz\r\n')   # Reset the device
            reset_response = self.sp.read_until(b'>')
            if (len(reset_response) == 0): raise Exception("No data received after reset attempt 1. Wrong serial port?")
            if (b'OK' not in reset_response):
                # Seems we interrupted a command, let's try again
                self.sp.write(b'atz\r\n')   # Reset the device
                reset_response = self.sp.read_until(b'>')
                if (len(reset_response) == 0): raise Exception("No data received after reset attempt 2. Wrong serial port?")
                if (reset_response[-1] != ord('>')): raise Exception("Unexpected reset response: ", (reset_response.decode("utf-8")))

            self.sp.write(b'atz\r\n')   # Reset the device
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("Device did not respond to reset")
            self.sp.write(b'atl1\r\n')  # Enable new line characters between commands/messages
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("Device did not accept configuration")
            
            self.sp.write(b'ati\r\n')   # Check ELM protocol version
            self.dev_ati_string = (self.sp.read_until(b'>').decode("utf-8"))
            self.dev_ati_string = re.search('\n(.*)\r',self.dev_ati_string).group(1)


            self.sp.write(b'sti\r\n')   # Check if STN device
            self.dev_sti_string = self.sp.read_until(b'>').decode("utf-8")
            self.dev_sti_string = re.search('\n(.*)\r',self.dev_sti_string).group(1)

            self.sp.write(b'dxi\r\n')   # Check if OBDX device
            self.dev_dxi_string = self.sp.read_until(b'>').decode("utf-8")
            self.dev_dxi_string = re.search('\n(.*?)( SN.*)?\r',self.dev_dxi_string).group(1)

            if ("?" not in self.dev_sti_string):
                self.dev_type = "STN"
                self.dev_string = self.dev_sti_string
            elif ("?" not in self.dev_dxi_string):
                self.dev_type = "OBDX"
                self.dev_string = self.dev_dxi_string
            else:
                self.dev_type = "ELM"
                self.dev_string = self.dev_ati_string

            print("Detected device was a",self.dev_type,"with a version string of:",self.dev_string)
            

            self.sp.write(b'atsp2\r\n') # Set protocol to VPW J1850
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("Device did not accept configuration")
            self.sp.write(b'ath1\r\n')  # Enable headers
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("Device did not accept configuration")
            self.sp.write(b'atma\r\n')  # Begin monitoring bus traffic
            if (len(self.sp.read_until(b'\r\n')) == 0): raise Exception("Device did not enter atma mode")
            print("Connected")
        else:
            self.fd = open(self.filename, 'r')
    
    def close(self):
        if self.serial:
            if self.sp.is_open:
                self.sp.write(b'a\r\n')
                time.sleep(1)
                self.sp.close()
        else:
            self.fd.close()
        
    def read(self):
        if self.serial:
            return self.sp.readline().decode("utf-8") 
        else:
            return self.fd.readline()
        
    def is_open(self):
        if self.serial:
            return self.sp.is_open
        return False
        
    

class VPW_frame:
    ''' 
    Functional Addresses commonly used on GM J1850 VPW Vehicles
    C is for command (request) - Bit 0 = 0
    S is for status (response) - Bit 0 = 1

    These are defined as well in SAE J2178-4

    A status is always a read
    A command is either a load or modify
    '''
    func_addresses = {
        0x0B:"Eng Air Intake",
        0x12:"Throttle",
        0x14:"AC Clutch",
        0x1A:"Engine RPM",
        0x24:"Wheels",
        0x28:"Vehicle Speed",
        0x2A:"Traction Control",
        0x32:"Brakes",
        0x34:"Steering",
        0x3A:"Trans",
        0x48:"Eng Coolant",
        0x4A:"Eng Oil",
        0x52:"Engine Sys",
        0x58:"Suspension",
        0x62:"Cruise Control",
        0x72:"Charging System",
        0x7A:"Odometer",
        0x82:"Fuel System",
        0x84:"Vehicle Motion",
        0x86:"Ign Switch",
        0x88:"Tell Tales (Warnings)",
        0x92:"Veh Security",
        0x96:"Chimes",
        0xB2:"HVAC",
        0xC4:"Door Locks",
        0xC6:"Extern Access",
        0xCE:"MFG Specific",
        0xD2:"Restraints",
        0xDA:"Exterior Lamps",
        0xDE:"Interior Lamps",
        0xE4:"Tires",
        0xE6:"Defrost",
        0xEA:"MFG Specific",
        0xF2:"Ext Environment",
        0xFA:"VIN",
        0xFE:"Network Control",
    }
    
    '''
    Physical Module Addresses Used in GM VPW-based Vehicles.
    These came from C5 vehicles, but should be consistent across similar 1997-2004 era GM vehicles
    A lot of data is missing when looking at vehicle logs

    Secondary IDs are used to identify the type of data being sent for functional addresses.
    Secondary ID is bits 5-0 of the first data byte.
    Q-bit is bit 7 of the first data byte.
    C-bit is bit 6 of the first data byte.

    Field for secondary IDs [Name, Q-bit = 0, Q-bit = 1, Ext Addr, PRN]
    Q bit is a single bit used to signal a binary state (i.e. On/Off)
    Ext Addr is the second data byte used to identify the physical location of the device
    PRN is the PRN of the message, which tells us how to do the math to get the actual value.
    '''
    secondary_ids = {
        0x12: {  # Throttle
            0x01: ["Sensor 1 Position", "", "", "", "0011"],
            0x02: ["Sensor 2 Position", "", "", "", "1035"],
            0x03: ["Sensor 3 Position", "", "", "", "1036"],
            0x10: ["Throttle Kicker", "E", "D", "", ""],
            0x11: ["Throttle Position", "", "", "", "1034"],
        },
        0x1A: {  # Engine RPM
            0x01: ["Low Res RPM", "", "", "", "1022"],
            0x02: ["High Res RPM", "", "", "", "000C"],
            0x10: ["High Res RPM", "", "", "", "000C"], # Found on 2001 C5 Z06
            0x20: ["Idle Speed", "Enabled", "Disabled", "", "1023"],
        },
        0x32: {  # Brakes
            0x03: ["ABS Active", "Y", "N", "", ""],
            0x04: ["ABS System On / Off", "On", "Off", "", ""],
            0x09: ["Fluid Life Reset", "R", "~R", "", ""],
            0x0A: ["System Faulted", "Y", "N", "", ""],
            0x10: ["Fluid Temperature", "", "", "", "281A"],
            0x11: ["Supply Pump Fluid Pressure", "", "", "", "2819"],
            0x12: ["Fluid Level - Percent", "", "", "", "2841"],
            0x13: ["Fluid Level - Volume", "", "", "", "2842"],
            0x14: ["Fluid Remaining Life", "", "", "", "2843"],
            0x16: ["Fluid Capacity", "", "", "", "2844"],
            0x20: ["Parking Brake Sw. Active", "Y", "N", "", ""],
            0x21: ["Torque Convertor Clutch - Brake Sw. Active", "Y", "N", "", ""],
            0x22: ["Brake Lamp - Brake Sw. Active", "Y", "N", "", ""],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", ""],
        },
        0x3A: { # Transmission
            0x01: ["Torque Convertor Lock(ed)", "Y", "N", "", ""],
            0x02: ["Clutch Enable", "E", "D", "", ""],
            0x03: ["Actual Gear Position w/ Shift in Progress", "Y", "N", "", "180E"],
            0x04: ["Range Selected (PRNDL position)", "", "", "", "1809"],
            0x05: ["Transfer Case (4WD)", "", "", "", "180A"],
            0x06: ["Commanded Gear", "", "", "", "180D"],
            0x07: ["Range Actual (PRNDL sense at transmission)", "", "", "", "1806"],
            0x08: ["Transmission Kickdown", "Y", "N", "", ""],
            0x09: ["Fluid Life Reset", "R", "~R", "", ""],
            0x0A: ["Fluid Temperature", "", "", "", "180B"],
            0x0B: ["Fluid Pressure", "", "", "", "180C"],
            0x0C: ["Fluid Level - Percent", "", "", "", "1801"],
            0x0D: ["Fluid Level - Volume", "", "", "", "1802"],
            0x0E: ["Fluid Remaining Life", "", "", "", "1804"],
            0x10: ["Fluid Capacity", "", "", "", "1803"],
            0x14: ["Park/Neutral Sw. Active", "Y", "N", "", ""],
            0x1D: ["Fluid Life Reset Sw. Active", "Y", "N", "", ""],
        },
        0x4A: { # Engine Oil
            0x09: ["Fluid Life Reset", "R", "~R", "", ""],
            0x10: ["Fluid Temperature", "", "", "", "102B"],
            0x11: ["Fluid Pressure", "", "", "", "102F"],
            0x12: ["Fluid Level - Percent", "", "", "", "102C"],
            0x13: ["Fluid Level - Volume", "", "", "", "102D"],
            0x14: ["Fluid Remaining Life", "", "", "", "1030"],
            0x15: ["Oil Viscosity", "", "", "", "103F"],
            0x16: ["Fluid Capacity", "", "", "", "102E"],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", ""],
            0x30: ["Fluid Temperature High", "Y", "N", "", ""],
            0x32: ["Low Oil Level", "Y", "N", "", ""],
        },
        0x52: { # Engine Systems - Other
            0x04: ["Engine Running", "Y", "N", "", ""],
        },
        0x72: {  # Charging System (Command ID)
            0x01: ["Charging Voltage", "", "", "", "6035"],
            0x02: ["Battery Voltage", "", "", "", "600A"],
            0x0A: ["Battery Current", "", "", "", "6038"],
            0x08: ["Cluster Voltage", "", "", "", "Z001"], # Found on 2001 C5 Z06
            0x21: ["Charging System Faulted", "Y", "N", "", ""],
        },
        0x82: {  # Fuel System
            0x0A: ["Unknown Value", "", "", "", ""], # Found on 2001 C5 Z06
            0x11: ["Fuel Pressure", "", "", "", "000A"],
            0x13: ["Fuel Level - Volume", "", "", "", "6006"],
            0x16: ["Fuel Capacity", "", "", "", "6007"],
            0x32: ["Low Fuel Level", "Y", "N", "", ""],
        },
        0x86: { # Ignition
            0x04: ["Ignition Switch Position", "", "", "", "1047"],
            0x05: ["Key-In-Ignition", "Y", "N", "", ""],
        },
        0x88: {  # Tell Tales (Warnings)
            0x01: ["Seatbelt", "On", "Off", "", ""],
            0x02: ["Service Engine Soon", "On", "Off", "", ""],
            0x03: ["Check Engine (MIL)", "On", "Off", "", ""],
            0x04: ["High Beam Indicator", "On", "Off", "", ""],
            0x05: ["Left Turn Indicator", "On", "Off", "", ""],
            0x06: ["Right Turn Indicator", "On", "Off", "", ""],
            0x07: ["Airbag", "On", "Off", "", ""],
            0x08: ["Anti-Lock Brake System Failed", "On", "Off", "0", ""],
            0x09: ["Traction Control System Failed", "On", "Off", "0", ""],
            0x0A: ["Security", "On", "Off", "0", ""],
            0x0B: ["Low Fuel", "On", "Off", "0", ""],
            0x0C: ["Low Coolant", "On", "Off", "0", ""],
            0x0D: ["Low Oil", "On", "Off", "0", ""],
            0x0E: ["Low Voltage", "On", "Off", "0", ""],
            0x0F: ["Upshift", "On", "Off", "0", ""],
            0x10: ["Low Washer Fluid", "On", "Off", "0", ""],
            0x11: ["Traction Control Active", "On", "Off", "0", ""],
            0x12: ["Alternator Failure", "On", "Off", "0", ""],
            0x13: ["Low Brake Fluid", "On", "Off", "0", ""],
            0x14: ["Overdrive", "On", "Off", "0", ""],
            0x15: ["Traction Control Disabled", "On", "Off", "0", ""],
            0x21: ["Convertible Latch Warning", "On", "Off", "0", ""],
            0x22: ["Super Lock System Warning", "On", "Off", "0", ""],
            0x23: ["Catalyst Over Temperature", "On", "Off", "0", ""],
            0x24: ["Vehicle Speed Control", "On", "Off", "0", ""]
        },
        0xB2: {  # HVAC (Climate Control)
            0x02: ["Blower Fan Speed", "", "", "", ""],
            0x06: ["Multi-Zone Mode", "E", "D", "", ""],
            0x07: ["Low Refrigerant", "Y", "N", "", ""],
            0x09: ["Fluid Life Reset", "R", "~R", "", ""],
            0x0A: ["HVAC Set Temperature", "", "", "8.2", "9820"],
            0x10: ["High Side Fluid Temperature", "", "", "", "9808"],
            0x11: ["High Side Fluid Pressure", "", "", "", "9813"],
            0x12: ["Fluid Charge - Percent", "", "", "", "980B"],
            0x13: ["Fluid Charge - Weight", "", "", "", "980C"],
            0x14: ["Fluid Remaining Life", "", "", "", "980D"],
            0x16: ["Fluid Capacity - Weight", "", "", "", "980E"],
            0x20: ["Low Side Fluid Temperature", "", "", "", "9809"],
            0x21: ["Low Side Fluid Pressure", "", "", "", "980A"],
            0x22: ["Fan Increment Speed Sw. Active", "Y", "N", "", ""],
            0x23: ["Fan Decrement Speed Sw. Active", "Y", "N", "", ""],
            0x26: ["Multi-Zone Mode Sw. Active", "Y", "N", "", ""],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", ""],
            0x2A: ["Increment Temp Sw. Active", "Y", "N", "", ""],
            0x2B: ["Decrement Temp Sw. Active", "Y", "N", "", ""],
        },
        0xC4: {  # Door Locks
            0x01: ["Lock", "L", "U", "8.5", ""],
            0x02: ["Unlock Enable", "E", "D", "8.5", ""],
            0x03: ["Lock Cylinder Secure", "Y", "N", "8.5", ""],
            0x04: ["Key-in-Lock Cylinder", "Y", "N", "8.5", ""],
            0x05: ["Master Controller Lock", "L", "N", "8.5", ""],
            0x06: ["Lock Cylinder State", "L", "U", "8.5", "A010"],
            0x07: ["Super/Double Lock", "L", "U", "8.5", ""],
            0x08: ["Remote Lock w/ Transmitter ID", "L", "U", "8.5", "C001"],
            0x09: ["Remote Lock", "L", "U", "8.5", ""],
            0x20: ["Lock Sw Active", "Y", "N", "8.5", ""],
            0x21: ["Unlock Sw Active", "Y", "N", "8.5", ""],
            0x22: ["Unlock Enable Sw Active", "Y", "N", "8.5", ""],
            0x25: ["Master Lock Sw Active", "Y", "N", "8.5", ""],
            0x26: ["Master Unlock Sw Active", "Y", "N", "8.5", ""],
        },
        0xC6: {  # External Access
            0x01: ["Open", "Y", "N", "8.5", ""],
            0x02: ["Close", "Y", "N", "8.5", ""],
            0x11: ["Remote Open/Close w/ Transmitter ID", "Open", "Close", "8.5", "C001"],
            0x12: ["Remote Open/Close", "Open", "Close", "8.5", ""],
            0x21: ["Ajar Sw. Active", "Y", "N", "8.5", ""],
            0x22: ["Door Handle Sw. Active", "Y", "N", "8.5", ""],
            0x23: ["Door Jamb Sw. Active", "Y", "N", "8.5", ""],
        },
        0xD2: { # Restraints
            0x01: ["Passive Restraint Enagaged", "Y", "N", "8.6", ""],
            0x02: ["Passive Restraint Retracted", "Y", "N", "8.6", ""],
            0x03: ["Passive Restraint Attached", "Y", "N", "8.6", ""],
            0x04: ["Seatbelt Attached", "Y", "N", "8.6", ""],
            0x05: ["Shoulder Adjustment Up Motion", "En", "Dis", "8.6", ""],
            0x06: ["Shoulder Adjustment Down Motion", "En", "Dis", "8.6", ""],
            0x07: ["Air Bag Deployed", "Y", "N", "8.6", ""],
        },
        0xDA: {  # Exterior Lamps
            0x01: ["Headlamp", "On", "Off", "8.8", ""],
            0x02: ["Tail Lamp", "On", "Off", "8.8", ""],
            0x03: ["Brake Lamp", "On", "Off", "8.8", ""],
            0x04: ["Park Lamp", "On", "Off", "8.8", ""],
            0x05: ["Turn Lamp", "On", "Off", "8.8", ""],
            0x06: ["High Beam Lamp", "On", "Off", "8.8", ""],
            0x07: ["Hazard Lamp", "On", "Off", "8.8", ""],
            0x08: ["Reverse Lamp", "On", "Off", "8.8", ""],
            0x09: ["Fog Lamp", "On", "Off", "8.8", ""],
            0x0A: ["Daytime Running Lamp", "On", "Off", "8.8", ""],
            0x0B: ["Spot Lamp", "On", "Off", "8.8", ""],
            0x0C: ["Cargo Lamp", "On", "Off", "8.8", ""],
            0x0D: ["Cornering Lamp", "On", "Off", "8.8", ""],
            0x0E: ["Driving Lamp", "On", "Off", "8.8", ""],
            0x0F: ["Coach Lamp", "On", "Off", "8.8", ""],
            0x10: ["Autolamp Delay", "E", "D", "8.8", "A014"],
            0x11: ["Flash-to-Pass", "E", "D", "8.8", ""],
            0x12: ["Remote Headlamp On/Off w/Transmitter ID", "On", "Off", "8.8", "C001"],
            0x13: ["Remote Headlamp", "On", "Off", "8.8", ""],
            0x21: ["Headlamp Sw. Active", "Y", "N", "8.8", ""],
            0x22: ["Right Turn Sw. Active", "Y", "N", "8.8", ""],
            0x24: ["Park Lamp Sw. Active", "Y", "N", "8.8", ""],
            0x25: ["Left Turn Sw. Active", "Y", "N", "8.8", ""],
            0x26: ["High Beam Sw. Active", "Y", "N", "8.8", ""],
            0x27: ["Hazard Sw. Active", "Y", "N", "8.8", ""],
            0x28: ["Fog Lamp Sw. Active", "Y", "N", "8.8", ""],
            0x29: ["Driving Lamp Sw. Active", "Y", "N", "8.8", ""]
        },
        0xDE: {  # Interior Lamps
            0x01: ["Courtesy Lamp", "On", "Off", "8.9", ""],
            0x02: ["Dome Lamp", "On", "Off", "8.9", ""], 
            0x03: ["Puddle Lamp", "On", "Off", "8.9", ""],
            0x04: ["Vanity Mirror Lamp", "On", "Off", "8.9", ""],
            0x05: ["Opera Lamp", "On", "Off", "8.9", ""],
            0x06: ["Reading Lamp", "On", "Off", "8.9", ""],
            0x07: ["Hood Lamp", "On", "Off", "8.9", ""],
            0x08: ["Trunk Lamp", "On", "Off", "8.9", ""],
            0x09: ["Glove Box Lamp", "On", "Off", "8.9", ""],
            0x10: ["Illuminated Entry", "E", "D", "0", ""],
            0x11: ["Display Brightness & External Lamps", "On", "Off", "0", "602B"],
            0x21: ["Courtesy Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x22: ["Dome Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x23: ["Puddle Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x24: ["Vanity Mirror Sw. Active", "Y", "N", "8.9", ""],
            0x25: ["Opera Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x26: ["Reading Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x27: ["Hood Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x28: ["Trunk Lamp Sw. Active", "Y", "N", "8.9", ""],
            0x29: ["Glove Box Lamp Sw. Active", "Y", "N", "8.9", ""],
        },
        0xF2: { # External Environment
            0x10: ["Outside Temperature", "", "", "", "602E"],
            0x11: ["Barometric Pressure", "", "", "", "1025"],
            0x13: ["Sun Load", "", "", "8.3", "9817"],
            0x15: ["Photo Cell Dark", "Yes", "No", "8.3", ""]
        },
        0xFA: {  # VIN
            0x01: ["VIN Dig 1", "", "", "", "E021"],
            0x02: ["VIN Digit 2-5", "", "", "", "E022"],
            0x03: ["VIN Digit 6-9", "", "", "", "E023"],
            0x04: ["VIN Digit 10-13", "", "", "", "E024"],
            0x05: ["VIN Digit 14-17", "", "", "", "E025"],
            0x06: ["VIN RSVD", "", "", "", ""],
            0x07: ["VIN RSVD", "", "", "", ""],
        },
        0xFE: {  # Network Control
            0x02: ["Bus Wake-Up", "Y", "N", "", ""],
            0x03: ["Node Alive", "Y", "N", "", ""],
            0x04: ["Node Sleep", "Y", "N", "", ""],
        }
    }
    
    ext_addresses = {
        "8.1": {  # Tires
            0x00: "ALL",
            0x10: "All Front",
            0x11: "Left Front",
            0x17: "Right Front",
            0x30: "All Rear",
            0x31: "Left Rear",
            0x37: "Right Rear",
            0x3C: "Spare Tire",
        },
        "8.2": {  # HVAC Zones
            0x00: "ALL",
            0x20: "All Front",
            0x22: "Driver Side Front",
            0x26: "Passenger Side Front",
            0x28: "All Rear",
            0x2A: "Driver Side Rear",
            0x2E: "Passenger Side Rear",
        },
        "8.3": {  # Window Wiper/Washer, Defrost, and photocell
            0x00: "ALL",
            0x1C: "Front",
            0x34: "Rear",
        },
        "8.4": {  # Mirrors
            0x00: "ALL",
            0x1A: "Driver Side",
            0x1C: "Rear View",
            0x1E: "Passenger Side",
        },
        "8.5": { # Doors and Door Locks
            0x00: "All Doors",
            0x14: "Hood",
            0x1E: "Pass Glove Box",
            0x20: "All Front Doors",
            0x22: "Driver Front Door",
            0x24: "Convertible Top",
            0x26: "Pass Front Door",
            0x28: "All Rear Doors",
            0x2A: "Rear Driver Door",
            0x2E: "Passenger Side Rear Door",
            0x31: "Left Side Fuel Door",
            0x34: "Trunk",
            0x37: "Right Side Fuel Door",
            0x3C: "Only or Rear Fuel Door",
        },
        "8.6": { # Seats and Restraints
            0x00: "ALL",
            0x20: "All Front",
            0x22: "Driver Side Front",
            0x24: "Front Center",
            0x26: "Passenger Side Front",
            0x28: "All Rear",
            0x2A: "Driver Side Rear",
            0x2C: "Rear Center",
            0x2E: "Passenger Side Rear",
            0x30: "All Rear - Rear (Van)",
            0x32: "Driver Side Rear - Rear (Van)",
            0x36: "Passenger Side Rear - Rear (Van)",
        },
        "8.7": {  # Windows
            0x00: "ALL",
            0x20: "All Front",
            0x22: "Driver Side Front",
            0x24: "Front Sun Roof",
            0x26: "Passenger Side Front",
            0x28: "All Rear",
            0x2A: "Driver Side Rear",
            0x2C: "Rear Sun Roof",
            0x2E: "Passenger Side Rear",
            0x34: "Rear Windshield",
        },
        "8.8": {  # External Lamps
            0x00: "ALL",
            0x01: "Left Side (Turn Signal)",
            0x07: "Right Side (Turn Signal)",
            0x08: "All Front",
            0x09: "Left Front",
            0x0F: "Right Front",
            0x38: "All Rear",
            0x39: "Left Rear",
            0x3C: "CHMSL",
            0x3F: "Right Rear",
        },
        "8.9": {  # Internal Lamps
            0x00: "ALL",
            0x20: "All Front",
            0x22: "Driver Side Front",
            0x26: "Passenger Side Front",
            0x28: "All Rear",
            0x2A: "Driver Side Rear",
            0x2C: "Dome Lamp",
            0x2E: "Passenger Side Rear",
        },
    }

    # Common PRD functions - define once, reuse many times
    # These are defined in SAE J2178-2
    # Note that payload array starts at the first data byte, not the secondary ID
    @staticmethod
    def _prd_unm_08_15(payload):
        """Convert 0-255 byte to 1/100 L per UNM-08-15"""
        return (payload[0]) / 100 if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_21(payload):
        """Convert 0-255 byte to 1/6 per UNM-08-21"""
        return (payload[0]) / 16 if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_32(payload):
        """Convert 0-255 byte to 1/16 per UNM-08-32"""
        return (payload[0]) / 16 if len(payload) > 0 else 0
    
    @staticmethod
    def _prd_unm_08_41(payload):
        """Convert 0-255 byte to 1/10 per UNM-08-41"""
        return (payload[0]) / 10 if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_61(payload):
        """Convert 0-255 byte to 0-100% per UNM-08-61"""
        return (payload[0] * 100) / 255 if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_71(payload):
        """Convert 0-255 byte to 0-100% per UNM-08-71"""
        return (payload[0] / 2) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_73(payload):
        """Convert 0-255 byte to -40 to 87.5°C per UNM-08-73"""
        return (payload[0] / 2) - 40 if len(payload) > 0 else 0
    
    @staticmethod
    def _prd_unm_08_101(payload):
        """Convert byte to 0 to 255 per UNM-08-101"""
        return (payload[0]) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_102(payload):
        """Convert byte to temperature in Celsius (-40 to 215°C) per UNM-08-102"""
        return payload[0] - 40 if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_125(payload):
        """Convert byte to 0 to 637 per UNM-08-125"""
        return (payload[0] * 5) / 2  if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_131(payload):
        """Convert byte to 0 to 765 per UNM-08-131"""
        return (payload[0] * 3) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_141(payload):
        """Convert byte to 0 to 1048 per UNM-08-141"""
        return (payload[0] * 4) if len(payload) > 0 else 0
    
    @staticmethod
    def _prd_unm_08_151(payload):
        """Convert byte to 0 to 2048 per UNM-08-151"""
        return (payload[0] * 8) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_155(payload):
        """Convert byte to 0 to 2550 g per UNM-08-155"""
        return (payload[0] * 10) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_159(payload):
        """Convert byte to 0 to 3570 per UNM-08-159"""
        return (payload[0] * 14) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_161(payload):
        """Convert byte to 0 to 4096 per UNM-08-161"""
        return (payload[0] * 16) if len(payload) > 0 else 0

    @staticmethod
    def _prd_unm_08_171(payload):
        """Convert byte to 0 to 8160 per UNM-08-171"""
        return (payload[0] * 32) if len(payload) > 0 else 0

    @staticmethod
    def _prd_sed_08_7(payload):
        """Convert byte to state string"""
        if len(payload) == 0:
            return None
        if (payload[0] == 0):
            return "Key Out"
        elif (payload[0] == 1):
            return "Key In Lock"
        elif (payload[0] == 2):
            return "Key In Unlock"
        else:
            return "Invalid"

    @staticmethod
    def _prd_sed_08_4(payload):
        """Convert byte to Transmission state string"""
        if len(payload) == 0:
            return None
        if (payload[0] == 0):
            return "Unknown"
        elif (payload[0] == 1):
            return "Reverse"
        elif (payload[0] == 2):
            return "Forward 1"
        elif (payload[0] == 4):
            return "Forward 2"
        elif (payload[0] == 8):
            return "Forward 3"
        elif (payload[0] == 16):
            return "Forward 4"
        elif (payload[0] == 32):
            return "Forward 5"
        elif (payload[0] == 64):
            return "Forward 6/Park"
        elif (payload[0] == 128):
            return "Neutral"
        else:
            return "Invalid"

    @staticmethod
    def _prd_sed_08_5(payload):
        """Convert byte to Ignition Switch Position state string"""
        if len(payload) == 0:
            return None
        if (payload[0] == 1):
            return "Accessory"
        elif (payload[0] == 2):
            return "Off / Lock"
        elif (payload[0] == 4):
            return "Off / Unlock"
        elif (payload[0] == 8):
            return "Run"
        elif (payload[0] == 16):
            return "Start"
        else:
            return "Invalid"

    @staticmethod
    def _prd_sed_08_6(payload):
        """Convert byte to Transfer Case state string"""
        if len(payload) == 0:
            return None
        if (payload[0] == 1):
            return "Neutral"
        elif (payload[0] == 2):
            return "2WD High"
        elif (payload[0] == 3):
            return "4WD Low"
        elif (payload[0] == 4):
            return "4WD High"
        else:
            return "Invalid"


    @staticmethod
    def _prd_unm_16_11(payload):
        """Convert byte to 0 to 655.35 per UNM-16-11"""
        return (payload[0] << 8 | payload[1]) / 100 if len(payload) > 1 else None

    @staticmethod
    def _prd_unm_16_31(payload):
        """Convert byte to 0 to 61383 per UNM-16-31"""
        return (payload[0] << 8 | payload[1]) / 4 if len(payload) > 1 else None


    @staticmethod
    def _prd_asc_32_1(payload):
        """Convert bytes to ASCII string per ASC-32-1"""
        return "".join(chr(b) for b in payload[0:4]) if len(payload) > 3 else None   

    @staticmethod
    def _prd_pkt_32_2(payload):
        """Convert bytes to ASCII string per PKT-32-2"""
        return chr(payload[3]) if len(payload) > 3 else None   


    # PRD (Parameter Response Data) array
    # Maps PRD ID to [unit, math_function]
    # Can reference common functions or define custom ones
    prd = {
        # Percentage functions (0-100%)
        "0011": ["%", _prd_unm_08_61],  # Generic percentage
        "102C": ["%", _prd_unm_08_71],  # Engine oil level - percent
        "1030": ["%", _prd_unm_08_61],  # Engine oil remaining life
        "1034": ["%", _prd_unm_08_61],  # Throttle Position %
        "1035": ["%", _prd_unm_08_61],  # Throttle Position %
        "1036": ["%", _prd_unm_08_61],  # Throttle Position %
        "1801": ["%", _prd_unm_08_71],  # Transmission fluid level - percent
        "1804": ["%", _prd_unm_08_61],  # Transmission fluid remaining life
        "2841": ["%", _prd_unm_08_71],  # 1/2% Step sizes with 0 to 100% UNM-08-71
        "2843": ["%", _prd_unm_08_61],  # Life percentage
        "602B": ["%", _prd_unm_08_61],  # Brightness percentage
        "980B": ["%", _prd_unm_08_61],  # Generic percentage
        "980D": ["%", _prd_unm_08_61],  # Generic percentage
        
        # Temperature functions (-40 to 215°C)
        "102B": ["°C", _prd_unm_08_102],  # Engine oil temperature
        "180B": ["°C", _prd_unm_08_102],  # Transmission fluid temperature
        "281A": ["°C", _prd_unm_08_102],  # Generic temperature
        "9808": ["°C", _prd_unm_08_102],  # High side temperature
        "9809": ["°C", _prd_unm_08_102],  # Low side temperature
        "9820": ["°C", _prd_unm_08_73],   # HVAC temperature
        "602E": ["°C", _prd_unm_08_73],   # Outside temperature
        
        # Pressure functions
        "000A": ["kPa", _prd_unm_08_131],  # Fuel pressure
        "102F": ["kPa", _prd_unm_08_141],  # Engine oil pressure
        "180C": ["kPa", _prd_unm_08_151],  # Transmission fluid pressure
        "2819": ["kPa", _prd_unm_08_171],  # Generic pressure
        "980A": ["kPa", _prd_unm_08_125],  # Low side pressure
        "9813": ["kPa", _prd_unm_08_159],  # High side pressure
        "1025": ["kPa", _prd_unm_08_101],  # Barometric pressure

        # Volume functions
        "102D": ["L", _prd_unm_08_41],  # Engine oil level - volume
        "102E": ["L", _prd_unm_08_41],  # Engine oil capacity
        "1802": ["L", _prd_unm_08_41],  # Transmission fluid level - volume
        "1803": ["L", _prd_unm_08_41],  # Transmission fluid capacity
        "2842": ["L", _prd_unm_08_15],  # Volume in liters
        "2844": ["L", _prd_unm_08_15],  # Capacity in liters
        "6006": ["L", _prd_unm_16_11],  # Volume in liters
        "6007": ["L", _prd_unm_16_11],  # Volume in liters

        # Weight functions
        "980C": ["g", _prd_unm_08_155],  # Weight in grams
        "980E": ["g", _prd_unm_08_155],  # Weight in grams

        # Time functions
        "A014": ["s", _prd_unm_08_101],  # Time in seconds

        # Motion/RPM functions
        "1022": ["rpm", _prd_unm_08_71],  # Low resolution RPM
        "000C": ["rpm", _prd_unm_16_31],  # High resolution RPM
        "1023": ["rpm", _prd_unm_08_161],  # Idle speed
        
        # Heat functions
        "9817": ["mW/CM^2", _prd_unm_08_71],  # Heat percentage

        # Voltage functions
        "6035": ["V", _prd_unm_08_32],  # Charging voltage
        "600A": ["V", _prd_unm_08_32],  # Battery voltage

        # Current functions
        "6038": ["A", _prd_unm_08_21],  # Battery current

        # State functions
        "A010": ["", _prd_sed_08_7],  # Door lock state
        "1047": ["", _prd_sed_08_5],  # Ignition switch position
        "1806": ["", _prd_sed_08_4],  # Range Actual (PRNDL sense at transmission)
        "1809": ["", _prd_sed_08_4],  # Range Selected (PRNDL position)
        "180A": ["", _prd_sed_08_6],  # Transfer Case (4WD)
        "180D": ["", _prd_sed_08_4],  # Commanded Gear
        "180E": ["", _prd_sed_08_4],  # Actual Gear Position w/ Shift in Progress

        # Other
        "103F": ["cSt.", _prd_unm_08_41],  # Oil viscosity
        "C001": ["", _prd_unm_08_101],  # Remote Transmitter ID/ID Number
        "E021": ["", _prd_pkt_32_2],  # VIN Dig 1
        "E022": ["", _prd_asc_32_1],  # VIN Dig 2-5
        "E023": ["", _prd_asc_32_1],  # VIN Dig 6-9
        "E024": ["", _prd_asc_32_1],  # VIN Dig 10-13
        "E025": ["", _prd_asc_32_1],  # VIN Dig 14-17   
       
        # Custom possibly wrong PRDs
        "Z001": ["V", _prd_unm_16_11],  # Cluster voltage (16 bit / 100)
        
        
        # Custom functions can still be defined inline if needed
        # "custom_id": ["unit", lambda payload: custom_calculation(payload)],
        # example: "custom_id": ["unit", lambda payload: (payload[0] * 1) / 2 if len(payload) > 0 else 0],
        
        # Add more PRD entries as needed...
    }

    phys_addresses = {
        0x10:"ECU",
        0x11:"ECM (CAN)", #C6 through BCM from CAN
        0x18:"TCM (CAN)", #C6 through BCM from CAN
        0x28:"ABS",
        0x40:"BCM",
        0x58:"SRS",
        0x60:"Cluster",
        0x62:"HUD", # C6
        0x80:"Radio",
        0x89:"Dig Radio Receiver", # C6
        0x97:"Onstar", # C6
        0x99:"HVAC",
        0xA0:"LDCM",
        0xA1:"RDCM",
        0xA4:"L Door Sw", #C6
        0xA6:"SCM",
        0xB0:"Remotes",
        0xC1:"RCDLR", #C6
        0xF1:"Ext Tool"
    }

    @staticmethod
    def is_valid(byteString):
        hex_digits = set('0123456789abcdefABCDEF xX')
        return all(c in hex_digits for c in byteString)
    
    @staticmethod
    def process(byteString):
        if (VPW_frame.is_valid(byteString) == False):
            return None
        
        try:
            byteArray = bytearray.fromhex(byteString)
        except:
            print ("Issue processing: ", byteString)
            return None
            
        if len(byteArray) < 5:
            return None

        mode = 'F'
        modeType = "?"
        priority = byteArray[0] >> 5
        wBit = byteArray[1] & 0x01
        cBit = (byteArray[3] & 0x40) >> 6
        ifrBit = (byteArray[0] & 0x08) >> 3
        addrMode = (byteArray[0] & 0x04) >> 2
        modeOp = "Load"

        if addrMode == 1: # Physical Address
            mode = 'P'
            modeType = (byteArray[0] & 0x0F) 
            if (modeType) == 0x0C:
                modeType = "N-N"
        else: # Functional Address
            mode = 'F'
            modeType = (byteArray[0] & 0x03)

            # ZZWC is ZZ of modeType, W of wBit, C of cBit
            zzwc = (modeType << 2) | (wBit << 1) | cBit

            if (zzwc == 0b0000):
                modeType = "F Comm/Status"
                modeOp = "Load"
            elif (zzwc == 0b0001):
                modeType = "F Comm/Status"
                modeOp = "Modify"
            elif (zzwc == 0b0010):
                modeType = "F Comm/Status"
                modeOp = "Report Status"
            elif (zzwc == 0b0011):
                modeType = "F Comm/Status"
                modeOp = "MFG Spec"
            elif (zzwc == 0b0100):
                modeType = "F Req/Query"
                modeOp = "Status Req"
            elif (zzwc == 0b0101):
                modeType = "F Req/Query"
                modeOp = "Report Ack"
            elif (zzwc == 0b0110):
                modeType = "F Req/Query"
                modeOp = "Command Req"
            elif (zzwc == 0b0111):
                modeType = "F Req/Query"
                modeOp = "Func Query"
            elif (zzwc == 0b1000):
                modeType = "F Ext Comm/Status"
                modeOp = "Load"
            elif (zzwc == 0b1001):
                modeType = "F Ext Comm/Status"
                modeOp = "Modify"
            elif (zzwc == 0b1010):
                modeType = "F Ext Comm/Status"
                modeOp = "Report Status"
            elif (zzwc == 0b1011):
                modeType = "F Ext Comm/Status"
                modeOp = "MFG Spec"
            elif (zzwc == 0b1100):
                modeType = "F Ext Req/Query"
                modeOp = "Status Req"
            elif (zzwc == 0b1101):
                modeType = "F Ext Req/Query"
                modeOp = "Report Ack"
            elif (zzwc == 0b1110):
                modeType = "F Ext Req/Query"
                modeOp = "Command Req"
            elif (zzwc == 0b1111):
                modeType = "F Ext Req/Query"
                modeOp = "Func Query"
            
        if (byteArray[0] & 0x10) == 0x10:
            mode = "?H"
        if (byteArray[0] & 0x08) == 0x00:
            mode = "?IFR"
            
            # Check for heart beat
        isHeartBeat = False
        if (byteArray[1] == 0xFF or byteArray[1] == 0xFE):
            if (len(byteArray) == 5):
                if (byteArray[3] == 0x03):
                    isHeartBeat = True

        return {'priority': priority, 'mode': mode, 'mode type': modeType, 'mode operation': modeOp, 'message': byteArray, 'heartbeat': isHeartBeat}
        
    @staticmethod
    def process_prd(prd_id, payload):
        """
        Process payload data using PRD (Parameter Response Data) calculations.
        
        Args:
            prd_id (str): The PRD ID from the secondary_ids entry
            payload (list): The message payload bytes
            
        Returns:
            tuple: (calculated_value, unit) or (None, None) if PRD not found
        """
        if prd_id in VPW_frame.prd:
            prd_info = VPW_frame.prd[prd_id]
            unit = prd_info[0]
            math_function = prd_info[1]
            
            # Check if we have enough data bytes for the calculation
            if len(payload) <= 1:
                return None, None
                
            try:
                # Handle string references to static methods
                if isinstance(math_function, str):
                    if hasattr(VPW_frame, math_function):
                        math_function = getattr(VPW_frame, math_function)
                    else:
                        print(f"Error: PRD {prd_id} function {math_function} not found")
                        return None, None
                
                # Handle both function references and lambda functions
                if callable(math_function):
                    calculated_value = math_function(payload)
                    # If the function returns None (insufficient data), return None
                    if calculated_value is None:
                        return None, None
                else:
                    print(f"Error: PRD {prd_id} math_function is not callable")
                    return None, None
                    
                return calculated_value, unit
            except (IndexError, ValueError, ZeroDivisionError) as e:
                print(f"Error processing PRD {prd_id}: {e}")
                return None, None
        else:
            return None, None

    @staticmethod
    def get_description(func_address, msg):
        """Get description for functional messages based on secondary ID
        Returns tuple: (data_value, full_description)
        """
        if (len(msg) == 0):
            return ("", "No Message")
        
        payload = msg["message"][3:]
        if len(payload) == 0:
            return ("", "No Payload")
        
        # Extract secondary ID from lower 6 bits of first payload byte
        secondary_id = payload[0] & 0x3F
        
        # Extract Q-bit (bit 7) from first payload byte
        q_bit = (payload[0] & 0x80) >> 7
        
        # Extract C-bit (bit 6) from first payload byte
        c_bit = (payload[0] & 0x40) >> 6
        
        # Extract TA[0] bit (bit 0 of target address)
        ta_bit_0 = func_address & 0x01
        
        # Determine operation type based on TA[0] and C-bit
        operation = ""
        if ta_bit_0 == 1 and c_bit == 0:
            operation = "Report"
        elif ta_bit_0 == 0 and c_bit == 0:
            operation = "Load"
        elif ta_bit_0 == 0 and c_bit == 1:
            operation = "Modify"
        else:
            operation = "Unknown"
        
        # Convert Status ID (odd) to Command ID (even) for lookup
        # Status IDs are always odd, Command IDs are always even
        if func_address & 0x01:  # If odd (Status ID)
            command_address = func_address - 1  # Convert to Command ID
        else:
            command_address = func_address  # Already Command ID
        
        # Look up in secondary_ids dictionary using the Command ID
        if command_address in VPW_frame.secondary_ids:
            if secondary_id in VPW_frame.secondary_ids[command_address]:
                secondary_info = VPW_frame.secondary_ids[command_address][secondary_id]
                if isinstance(secondary_info, str):
                    return ("", f"{secondary_info} ({msg['mode operation']})")
                elif isinstance(secondary_info, (list, set, tuple)) and len(secondary_info) > 0:
                    # Convert to list and get the first element (Name)
                    info_list = list(secondary_info)
                    base_description = info_list[0]  # Return the Name (first element)
                    
                    # Add Q-bit text if available (but not for Status Req or Report Ack messages)
                    q_text = ""
                    if len(info_list) >= 3 and msg.get('mode operation') not in ['Status Req', 'Report Ack']:  # Make sure we have at least 3 fields and not Status Req/Report Ack
                        if q_bit == 1 and len(info_list) > 1:
                            # Q-bit is 1, use 2nd field (index 1)
                            q_text = info_list[1]
                        elif q_bit == 0 and len(info_list) > 2:
                            # Q-bit is 0, use 3rd field (index 2)
                            q_text = info_list[2]
                    
                    # Check message type to determine processing logic
                    message_type = msg.get('mode type', '')
                    is_extended = 'F Ext' in message_type
                    
                    # Check for external address lookup (4th field) - only for F Ext messages
                    ext_address_text = ""
                    if is_extended and len(info_list) >= 4 and len(payload) > 1:  # Only for F Ext messages
                        ext_addr_key = info_list[3]  # 4th field (index 3)
                        if ext_addr_key and ext_addr_key != "0" and ext_addr_key in VPW_frame.ext_addresses:
                            # Look up the second data byte in the ext_addresses
                            second_byte = payload[1]
                            if second_byte in VPW_frame.ext_addresses[ext_addr_key]:
                                ext_address_text = f" - {VPW_frame.ext_addresses[ext_addr_key][second_byte]}"
                    
                    # Process PRD if available (5th field) - for both F and F Ext messages
                    data_value = ""
                    if len(info_list) >= 5 and len(info_list[4]) > 0:  # Both F and F Ext messages can have PRD
                        prd_id = info_list[4]  # 5th field (index 4) - PRD ID
                        if prd_id and prd_id != "":
                            if is_extended:
                                # For F Ext messages, PRD data starts at 3rd byte (skip secondary ID and ext address)
                                data_payload = payload[2:] if len(payload) > 2 else []
                            else:
                                # For regular F messages, PRD data starts at 2nd byte (skip secondary ID)
                                data_payload = payload[1:] if len(payload) > 1 else []
                            
                            calculated_value, unit = VPW_frame.process_prd(prd_id, data_payload)
                            if calculated_value is not None:
                                if isinstance(calculated_value, (int, float)):
                                    data_value = f"{calculated_value:.2f} {unit}"
                                else:
                                    data_value = f"{calculated_value} {unit}"
                    
                    # If no PRD data and message type is 'Report Stat', show Q-bit value in Data column
                    if not data_value and msg.get('mode operation') == 'Report Stat' and len(info_list) >= 3:
                        if q_bit == 1 and len(info_list) > 1:
                            data_value = info_list[1]  # Q-bit is 1, use 2nd field
                        elif q_bit == 0 and len(info_list) > 2:
                            data_value = info_list[2]  # Q-bit is 0, use 3rd field
                    
                    # Combine all parts (excluding PRD data since it's now in Data column)
                    result = base_description
                    if q_text:
                        result += f": {q_text}"
                    if ext_address_text:
                        result += ext_address_text
                    
                    # Add operation type at the end
                    result += f" ({msg['mode operation']})"
                    
                    return (data_value, result)
    
        #return f"Unknown SecID: {secondary_id:02X}"
        return ("", f"({msg['mode operation']})")
        
    
        
'''
Message Manager Class is used to handle displaying the messages received
'''
class MessageManager():
    def __init__(self, UIHook):
        self.UIHook = UIHook
        
        self.messageSummary = []
        self.messageHistory = []
        
        # Filtering settings
        self.filter_compare_bytes = 2
        self.hide_heartbeat = False
        
    def new_message(self, input_string):
        # Send string off to get parsed
        inString = input_string.rstrip()
        newMsg = VPW_frame.process(inString)
        
        # If object is NoneType, then it failed to parse. Potentially invalid packet
        if not (newMsg):
            print ("Invalid message recieved in new_message: ", input_string)
            return
        
        #Decode address
        taModule = "NA"
        saModule = "NA"
        description = "NA"
        
        if (newMsg["mode"] == "F"):
            # For functional messages, always try to decode the TA
            target_addr = newMsg["message"][1]
            
            # Convert Status ID (odd) to Command ID (even) for lookup
            if target_addr & 0x01:  # If odd (Status ID)
                command_addr = target_addr - 1  # Convert to Command ID
                prefix = "(S) "
            else:
                command_addr = target_addr  # Already Command ID
                prefix = "(C) "
            
            # Look up the command address in func_addresses
            if command_addr in VPW_frame.func_addresses:
                taModule = f"${target_addr:02X} {prefix}{VPW_frame.func_addresses[command_addr]}"
            else:
                taModule = f"${target_addr:02X}"
            
            # Get description for ALL functional messages
            data_value, description = VPW_frame.get_description(target_addr, newMsg)
        else:
            if newMsg["message"][1] in VPW_frame.phys_addresses:
                taModule = str("${:02X}".format(newMsg["message"][1])+" "+VPW_frame.phys_addresses[newMsg["message"][1]])
            else:
                taModule = "${:02X}".format(newMsg["message"][1])
            data_value = ""  # No data value for physical messages
                
        if newMsg["message"][2] in VPW_frame.phys_addresses:
            saModule = str("${:02X}".format(newMsg["message"][2])+" "+VPW_frame.phys_addresses[newMsg["message"][2]])
        else:
            saModule = "${:02X}".format(newMsg["message"][2])
        
        # Append message to data frame (now includes data value and description)
        self.messageHistory.append([len(self.messageHistory), newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:], inString, data_value, description])

        tempMsg = self.messageHistory[-1]
        
        # See if an existing message exists
        summaryInd = self.find_existing_summary(tempMsg)
        self.UIHook.new_message(tempMsg)
        self.UIHook.update_status_bar( len(self.messageHistory))
        
        # If hide heart beat is enabled, we'll just skip adding it to the summary altogether
        if (newMsg["heartbeat"] and self.UIHook.hideHeartbeats.get()):
            return
        
        if (summaryInd == -1):
            self.messageSummary.append([len(self.messageSummary), 0, tempMsg[0], newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:], data_value, description])
            
            self.UIHook.new_message_summary(self.messageSummary[-1])
        else:
            # Otherwise we need to update the record
            self.messageSummary[summaryInd][1] += 1
            self.messageSummary[summaryInd][2] = tempMsg[0]
            self.messageSummary[summaryInd][9] = tempMsg[7]
            self.messageSummary[summaryInd][10] = data_value  # Update data value
            self.messageSummary[summaryInd][11] = description  # Update description too
            
            self.UIHook.update_message_summary(summaryInd, self.messageSummary[summaryInd])
        
        
    def find_existing_summary(self, msg):
        if (len(self.messageSummary) == 0):
            return -1
            
        byteCompare = self.UIHook.messageUniqueByte.get()
        if (byteCompare != "All"):
            byteCompare = int(self.UIHook.messageUniqueByte.get())
        
        rows = []    
        for row in self.messageSummary:
            if (row[3] == msg[1] and row[4] == msg[2] and row[5] == msg[3]):
                rows.append(row)
    
        if (len(rows) > 0):
        
            # TODO: This can be optimized by having the if statement once and a loop under them
            # Found some rows that met the TA and SA, now to compare payload
            
                if (byteCompare == "All"):
                    for row in rows:
                        if (row[9] == msg[7]):
                            #print ("Found index: ",index, "  rows\n\r", rows)
                            return row[0]
                elif (byteCompare == 0):
                    for row in rows:    
                        return row[0]
                elif (byteCompare == 1):
                    for row in rows:
                        if (row[9][0] == msg[7][0]):
                            return row[0]
                elif (byteCompare == 2):
                    for row in rows:
                        if (row[9][0] == msg[7][0]):
                            if (len(row[9]) == 1):
                                return row[0]
                            else:
                                if (row[9][1] == msg[7][1]):
                                    return row[0]                        
                        
            
        return -1
    
    def clear_messages(self):
        return
        
        
'''
This class is used to run the serial/OBD class in a separate thread
'''
class ThreadedTask(threading.Thread):
    def __init__(self, gui, queue, file_path):
        threading.Thread.__init__(self)
        self.gui = gui
        self.file_path = file_path
        self.stop_var = False
        self.obd = None
        self.queue = queue
        self.start_time = None
        self.end_time = None
        self.message_count = 0
        
    def run(self):
        if (self.obd):
            self.obd.close()

        # Reset and start timing
        self.reset_stats()
        self.start_time = time.perf_counter()
        print(f"Starting file processing: {self.file_path}")

        self.obd = OBD(self.file_path)
        self.obd.open()
        self.gui.update_obd_status(True,self.obd.dev_string)
        threadPointer = threading.current_thread()

        
        while (self.stop_var == False):
            try:
                #time.sleep(0.1)  # Simulate long running process
                line = self.obd.read()
                if self.stop_var:
                    break

                if not line:
                    # End of file reached
                    self.end_time = time.perf_counter()
                    self.print_performance_stats()
                    break
                    
                # Count and queue the message
                self.message_count += 1
                self.queue.put(line)
            except Exception as e:
                print(f"Exception in file reading thread: {e}")
                self.end_time = time.perf_counter()
                self.print_performance_stats()
                break
        
        self.obd.close()

    def stop(self):
        self.stop_var = True
        # If we haven't set end_time yet, set it now for partial stats
        if self.start_time and not self.end_time:
            self.end_time = time.perf_counter()
            print("File processing stopped by user")
            self.print_performance_stats()
    
    def reset_stats(self):
        """Reset performance statistics"""
        self.start_time = None
        self.end_time = None
        self.message_count = 0
    
    def print_performance_stats(self):
        """Print performance statistics for file processing"""
        if self.start_time and self.end_time:
            total_time = self.end_time - self.start_time
            messages_per_second = self.message_count / total_time if total_time > 0 else 0
            
            print("=" * 70)
            print("FILE PROCESSING PERFORMANCE STATISTICS")
            print("=" * 70)
            print(f"File: {self.file_path}")
            print(f"Total messages processed: {self.message_count}")
            print(f"Total processing time: {total_time:.6f} seconds")
            print(f"Total processing time: {total_time * 1000:.3f} milliseconds")
            print(f"Total processing time: {total_time * 1000000:.1f} microseconds")
            print(f"Messages per second: {messages_per_second:.2f}")
            if self.message_count > 0:
                avg_time_seconds = total_time / self.message_count
                avg_time_ms = avg_time_seconds * 1000
                avg_time_us = avg_time_seconds * 1000000
                print(f"Average time per message: {avg_time_seconds:.6f} seconds")
                print(f"Average time per message: {avg_time_ms:.3f} milliseconds")
                print(f"Average time per message: {avg_time_us:.1f} microseconds")
            else:
                print("Average time per message: N/A")
            print("=" * 70)
        else:
            print("Performance stats not available - timing data incomplete")
    
'''
Main application class that handles the GUI
'''
class Application(tk.Frame):
    def __init__(self, root):
        self.root = root
        self.thread_reading = None
        self.queue = queue.Queue()
        self.initialize_user_interface()
        self.update_status_bar(False)
        self.mm = MessageManager(self)
        # Start the queue processing
        self.update_ui()
 
    def initialize_user_interface(self):
        # Configure the root object for the Application
        self.root.title("VPW Analyzer")
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_rowconfigure(2, weight=0)
        self.root.grid_rowconfigure(3, weight=3)
        self.root.grid_rowconfigure(4, weight=0)
        
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(2, minsize=10)
        self.root.grid_columnconfigure(4, minsize=10)
        self.root.config(background="Grey")
        
        ''' Variables for GUI '''
        self.statusBarString = tk.StringVar()
        self.statusBarOBDString = tk.StringVar()
        self.messageTreeLock = tk.BooleanVar()
        self.hideHeartbeats = tk.BooleanVar()
        self.messageUniqueByte = tk.StringVar()
        self.messageUniqueByte.set("2")
        
 
        
        
        
        ''' Summary Tree at the top '''
        self.summaryTreeLabel = tk.Label(self.root, text="Summary Messages")
        self.summaryTreeLabel.grid(row=0, column=0, sticky=tk.W)
        self.summaryTree = ttk.Treeview(self.root, columns=( 'Last MID', '# Msgs', 'Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Data', 'Description'))
        self.summaryTreeScroll = ttk.Scrollbar(self.root)
        self.summaryTreeScroll.configure(command=self.summaryTree.yview)
        self.summaryTree.configure(yscrollcommand=self.summaryTreeScroll.set)
        
        
        # Set the heading (Attribute Names)
        self.summaryTree.heading('#0', text='SID')
        self.summaryTree.heading('#1', text='Last MID')
        self.summaryTree.heading('#2', text='# Msgs')
        self.summaryTree.heading('#3', text='Hdr')
        self.summaryTree.heading('#4', text='Priority')
        self.summaryTree.heading('#5', text='Mode')
        self.summaryTree.heading('#6', text='Type')
        self.summaryTree.heading('#7', text='TA')
        self.summaryTree.heading('#8', text='SA')
        self.summaryTree.heading('#9', text='Payload')
        self.summaryTree.heading('#10', text='Data')
        self.summaryTree.heading('#11', text='Description')
        
 
        # Specify attributes of the columns (We want to stretch it!)
        self.summaryTree.column('#0', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#1', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#2', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#3', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#4', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#5', minwidth=30, width=40, stretch=tk.YES)
        self.summaryTree.column('#6', minwidth=30, width=70, stretch=tk.YES)
        self.summaryTree.column('#7', minwidth=30, width=200, stretch=tk.YES)
        self.summaryTree.column('#8', minwidth=30, width=80, stretch=tk.YES)
        self.summaryTree.column('#9', minwidth=50, width=200, stretch=tk.YES)
        self.summaryTree.column('#10', minwidth=50, width=100, stretch=tk.YES)
        self.summaryTree.column('#11', minwidth=50, width=300, stretch=tk.YES)
 
        self.summaryTree.grid(row=1, column=0, sticky='nsew')
        self.summaryTreeScroll.grid(row=1, column=1, sticky='nsw')
        
        # Bind double-click event to summary tree
        self.summaryTree.bind('<Double-1>', self.on_summary_double_click)
        
        
        
        
        
        ''' Message Tree '''
        self.messageTree_Label = tk.Label(self.root, text="Message history")
        self.messageTree_Label.grid(row=2, column=0,  sticky=tk.W)
        self.messageTree_checkbox = tk.Checkbutton(self.root, text="Lock to most recent", variable=self.messageTreeLock, onvalue=True, offvalue=False)
        self.messageTree_checkbox.grid(row=2,column=0, sticky=tk.E)
        
        # Set the treeview for the raw transaction table
        self.messageTree = ttk.Treeview(self.root, columns=('Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Data', 'Description'))
        self.messageTreeScroll = ttk.Scrollbar(self.root)
        self.messageTreeScroll.configure(command=self.messageTree.yview)
        self.messageTree.configure(yscrollcommand=self.messageTreeScroll.set)
        
        # Set the heading (Attribute Names)
        self.messageTree.heading('#0', text='MID')
        self.messageTree.heading('#1', text='Hdr')
        self.messageTree.heading('#2', text='Priority')
        self.messageTree.heading('#3', text='Mode')
        self.messageTree.heading('#4', text='Type')
        self.messageTree.heading('#5', text='TA')
        self.messageTree.heading('#6', text='SA')
        self.messageTree.heading('#7', text='Payload')
        self.messageTree.heading('#8', text='Data')
        self.messageTree.heading('#9', text='Description')
        
 
        # Specify attributes of the columns (We want to stretch it!)
        self.messageTree.column('#0', minwidth=30, width=40, stretch=tk.YES)
        self.messageTree.column('#1', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#2', minwidth=40, width=40, stretch=tk.YES)
        self.messageTree.column('#3', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#4', minwidth=30, width=60, stretch=tk.YES)
        self.messageTree.column('#5', minwidth=30, width=170, stretch=tk.YES)
        self.messageTree.column('#6', minwidth=30, width=80, stretch=tk.YES)
        self.messageTree.column('#7', minwidth=50, width=200, stretch=tk.YES)
        self.messageTree.column('#8', minwidth=50, width=100, stretch=tk.YES)
        self.messageTree.column('#9', minwidth=50, width=300, stretch=tk.YES)
 
        self.messageTree.grid(row=3, column=0, sticky='nsew')
        self.messageTreeScroll.grid(row=3, column=1, sticky='nsw')
        
        # Bind double-click event to message tree
        self.messageTree.bind('<Double-1>', self.on_message_double_click)
        
        ''' Configuration Frame '''
        self.config_frame = tk.Frame(self.root, borderwidth = 1)
        self.config_frame.grid(row=1, column = 3, rowspan=1, sticky='nsew')
        self.config_frame.grid_rowconfigure(90, weight=1)
        
        # Define the different GUI widgets
        self.config_label = tk.Label(self.config_frame, text="OBD II Configuration")
        self.config_label.grid(row=0, column=0, columnspan=3, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=1, columnspan = 3, sticky='ew')
        self.serial_label = tk.Label(self.config_frame, text="OBD Device Serial Port")
        self.serial_port_entry = tk.Entry(self.config_frame)
        self.serial_browse_button = tk.Button(self.config_frame, text="Browse", command=self.browse_file)
        self.serial_label.grid(row=2, column=0, sticky=tk.W)
        self.serial_port_entry.grid(row=2, column=1, sticky='ew')
        self.serial_browse_button.grid(row=2, column=2, padx=(5, 0))
        
        # Enable standard key bindings for text selection
        self.serial_port_entry.bind('<Control-a>', self.select_all_text)
        self.serial_port_entry.bind('<Control-A>', self.select_all_text)
 
        self.idnumber_label = tk.Label(self.config_frame, text="Raw Line")
        self.idnumber_entry = tk.Entry(self.config_frame)
        self.idnumber_label.grid(row=3, column=0, sticky=tk.W)
        self.idnumber_entry.grid(row=3, column=1)
        
        # Enable standard key bindings for text selection
        self.idnumber_entry.bind('<Control-a>', self.select_all_text)
        self.idnumber_entry.bind('<Control-A>', self.select_all_text)
 
 
        self.submit_button = tk.Button(self.config_frame, text="Parse", command=self.insert_data)
        self.submit_button.grid(row=4, column=1, sticky=tk.W)
        self.read_button = tk.Button(self.config_frame, text="Read", command=self.read_file)
        self.read_button.grid(row=4, column=1, sticky='e')
 
 
 
 
        # View settings
        self.config_label = tk.Label(self.config_frame, text="View Settings")
        self.config_label.grid(row=4, column=0, columnspan=3, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=5, columnspan = 3, sticky='ew')
        
        self.view_hideHeartbeats = tk.Checkbutton(self.config_frame, text="Hide Module Heartbeats", variable=self.hideHeartbeats, onvalue=True, offvalue=False)
        self.view_hideHeartbeats.grid(row=6,column=0, sticky=tk.E)
        
        self.view_uniqueByte_label = tk.Label(self.config_frame, text="Compare First # Bytes")
        self.view_uniqueByte_label.grid(row=7,column=0)
        self.view_uniqueByte = tk.OptionMenu(self.config_frame, self.messageUniqueByte, "0", "1", "2", "All")
        self.view_uniqueByte.grid(row=7,column=1, sticky=tk.W)
        
        self.delete_button = tk.Button(self.config_frame, text="Clear Message Logs", command=self.delete_data)
        self.delete_button.grid(row=100, column=0)
        
        self.delete_button = tk.Button(self.config_frame, text="Export Logs", command=self.export_log)
        self.delete_button.grid(row=100, column=1)
 
        
        
        
 
 
 
        ''' Transmit Message Frame '''
        self.transmit_frame = tk.Frame(self.root, borderwidth = 1)
        self.transmit_frame.grid(row=3, column = 3, rowspan=1, sticky='nsew')
        self.transmit_frame.grid_rowconfigure(5, minsize=10)
        self.transmit_frame.grid_rowconfigure(90, weight=1)
        
        self.config_label = tk.Label(self.transmit_frame, text="Transmit Frame")
        self.config_label.grid(row=0, column=0, columnspan=2, sticky=tk.W)
        config_sep = ttk.Separator(self.transmit_frame, orient='horizontal')
        config_sep.grid(row=1, columnspan = 2, sticky='ew')
        
        

        self.header_label = tk.Label(self.transmit_frame, text="Header")
        self.header_label.grid(row=2, column=0)
        self.header_entry = tk.Entry(self.transmit_frame)
        self.header_entry.grid(row=2, column=1)
        self.header_entry.insert(0, "8C F1 10")
        # Enable standard key bindings for text selection
        self.header_entry.bind('<Control-a>', self.select_all_text)
        self.header_entry.bind('<Control-A>', self.select_all_text)
        
        self.payload_label = tk.Label(self.transmit_frame, text="Payload")
        self.payload_label.grid(row=3, column=0)
        self.payload_entry = tk.Entry(self.transmit_frame)
        self.payload_entry.grid(row=3, column=1)
        self.payload_entry.insert(0, "24 00")
        # Enable standard key bindings for text selection
        self.payload_entry.bind('<Control-a>', self.select_all_text)
        self.payload_entry.bind('<Control-A>', self.select_all_text)
        
        self.send_button = tk.Button(self.transmit_frame, text="Send")
        self.send_button.grid(row=4, column=1, sticky='s')
        
        config_sep = ttk.Separator(self.transmit_frame, orient='horizontal')
        config_sep.grid(row=5, columnspan = 2, sticky='ew')
        
        self.send_selected_button = tk.Button(self.transmit_frame, text="Send Selected Message")
        self.send_selected_button.grid(row=6, column=0, sticky='s')
        
        self.help_button = tk.Button(self.transmit_frame, text="Help", command=self.show_help)
        self.help_button.grid(row=100, column=1, sticky='s')
        
        self.exit_button = tk.Button(self.transmit_frame, text="Exit Program", command=self.on_app_close)
        self.exit_button.grid(row=100, column=0, sticky='s')
        
    
        
        ''' Status Bar '''
        self.statusBar = tk.Label(self.root, textvariable=self.statusBarString, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.statusBar.grid(row=4, column=0, columnspan=5, sticky='nsew')
        self.statusBarOBD = tk.Label(self.root, textvariable=self.statusBarOBDString, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.statusBarOBD.grid(row=4, column=2, columnspan=5, sticky='nsew')
        
        
        ''' Reset any variables '''
        self.sid = 0
        self.mid = 0
        self.statusBarString.set("Messages: 0")
        self.statusBarOBDString.set("OBD: Disconnected")
 
 
    def update_status_bar(self, messages=0, connected=False):
        string = "Messages: " + str(messages)
            
        self.statusBarString.set(string)

    def update_message_count(self, messages=0):
        self.messages_receieved = messages
        

    def update_obd_status(self,connected=False,dev_version=""):
        if connected:
            self.statusBarOBDString.set("OBD: Connected - " + str(dev_version))
        else:
            self.statusBarOBDString.set(str("OBD: Disconnected"))
    
    def browse_file(self):
        """Open file dialog to select a VPW log file"""
        file_path = filedialog.askopenfilename(
            title="Select VPW Log File or Serial Port",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.serial_port_entry.delete(0, tk.END)
            self.serial_port_entry.insert(0, file_path)
    
    def insert_data(self):
        rawString = self.idnumber_entry.get()
        self.mm.new_message(rawString)
        
    def export_log(self):
        """Export logs to a user-selected file"""
        file_path = filedialog.asksaveasfilename(
            title="Export VPW Logs",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ],
            initialfile="export.txt"
        )
        
        if file_path:
            try:
                with open(file_path, "w") as fexport:
                    for line in self.mm.messageHistory:
                        fexport.write(line[-1] + "\r\n")
                print(f"Logs exported successfully to: {file_path}")
            except Exception as e:
                print(f"Error exporting logs: {e}")
                messagebox.showerror("Export Error", f"Failed to export logs:\n{e}")
        

    def new_message(self, newMsg):        
        # Print the message to the message history tree
        self.messageTree.insert('', 'end', iid=newMsg[0], text=str(newMsg[0]),
                             values=("{:02X}".format(newMsg[1]), newMsg[4], newMsg[5],
                             newMsg[6], newMsg[2], newMsg[3], str(" ".join(["{:02X}".format(x) for x in newMsg[7][:-1]])), newMsg[9], newMsg[10]))

        # If the scroll lock is enabled, then scroll down
        if (self.messageTreeLock.get()):
            self.messageTree.yview_moveto(1)
            
        self.update_status_bar()
        
        
        
    def new_message_summary(self, newMsg):        
        # Print the message to the message history tree
        self.summaryTree.insert('', 'end', iid=newMsg[0], text=str(newMsg[0]),
                             values=(newMsg[0], 0, "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7],
                             newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]])), newMsg[10], newMsg[11]))
        #self.sid = self.sid + 1
        
        
    def update_message_summary(self, index, newMsg):
        values = self.summaryTree.item(index)
        #print ("Updating UI: ", values, "and", newMsg)
        try:
            self.summaryTree.item(index, text=str(index),
                             values=(newMsg[2], newMsg[1], "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7], newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]])), newMsg[10], newMsg[11]))
        except:
            print ("Issue updating index, ", newMsg)
            for child in self.summaryTree.get_children():
                print(self.summaryTree.item(child)["values"])
    
    
    def delete_data(self):
        #row_id = int(self.summaryTree.focus())
        #self.summaryTreeview.delete(row_id)
        for i in self.summaryTree.get_children():
            self.summaryTree.delete(i)
            
        for i in self.messageTree.get_children():
            self.messageTree.delete(i)
            
        self.mm = MessageManager(self)
            
        self.mid = 0
        self.sid = 0
        
    def read_file(self):
        file_path = self.serial_port_entry.get()
        
        if (self.thread_reading):
            # A thread exists already. Must mean it's already open. We must close/destroy it
            self.thread_reading.stop()
            self.thread_reading.join(3)
            if (self.thread_reading.is_alive()):
                print("Error ending thread...")
        self.thread_reading = ThreadedTask(self, self.queue, file_path)
        self.thread_reading.start()

    def update_ui(self):
        # Process any messages in the queue
        try:
            while True:
                line = self.queue.get_nowait()
                self.mm.new_message(line)
        except queue.Empty:
            pass
        
        # Schedule the next update
        self.root.after(100, self.update_ui)
    
    def select_all_text(self, event):
        """Select all text in the widget that triggered the event"""
        event.widget.select_range(0, tk.END)
        return "break"  # Prevent default behavior
    
    def on_summary_double_click(self, event):
        """Handle double-click on summary tree to populate transmit frame"""
        item = self.summaryTree.selection()[0] if self.summaryTree.selection() else None
        if item:
            values = self.summaryTree.item(item, 'values')
            self.populate_transmit_frame(values, is_summary=True)
    
    def on_message_double_click(self, event):
        """Handle double-click on message tree to populate transmit frame"""
        item = self.messageTree.selection()[0] if self.messageTree.selection() else None
        if item:
            values = self.messageTree.item(item, 'values')
            self.populate_transmit_frame(values, is_summary=False)
    
    def populate_transmit_frame(self, values, is_summary=False):
        """Populate transmit frame fields with data from selected row"""
        try:
            if is_summary:
                # Summary tree columns: 'Last MID', '# Msgs', 'Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Data', 'Description'
                if len(values) >= 10:
                    hdr = values[2]    # Hdr column (e.g., "8C")
                    ta = values[6]     # TA column (e.g., "$83 (S) Fuel System")
                    sa = values[7]     # SA column (e.g., "$10 ECU")
                    payload = values[8]  # Payload column
                else:
                    print("Error: Not enough columns in summary tree data")
                    return
            else:
                # Message tree columns: 'Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Data', 'Description'
                if len(values) >= 8:
                    hdr = values[0]    # Hdr column (e.g., "8C")
                    ta = values[4]     # TA column (e.g., "$83 (S) Fuel System")
                    sa = values[5]     # SA column (e.g., "$10 ECU")
                    payload = values[6]  # Payload column
                else:
                    print("Error: Not enough columns in message tree data")
                    return
            
            # Extract hex values from TA and SA columns
            ta_hex = self.extract_hex_from_column(ta)
            sa_hex = self.extract_hex_from_column(sa)
            
            # Construct the header: Hdr + TA + SA
            if ta_hex and sa_hex:
                header = f"{hdr} {ta_hex} {sa_hex}"
            else:
                header = hdr  # Fallback to just the Hdr column if extraction fails
            
            # Clear existing values
            self.header_entry.delete(0, tk.END)
            self.payload_entry.delete(0, tk.END)
            
            # Populate the fields
            self.header_entry.insert(0, header)
            self.payload_entry.insert(0, payload)
            
        except Exception as e:
            print(f"Error populating transmit frame: {e}")
    
    def extract_hex_from_column(self, column_value):
        """Extract hex value from TA/SA column (e.g., '$83 (S) Fuel System' -> '83')"""
        try:
            if not column_value:
                return None
            
            # Look for hex pattern like $83, 83, 0x83, etc.
            import re
            hex_match = re.search(r'[\$]?([0-9A-Fa-f]{2})', column_value)
            if hex_match:
                return hex_match.group(1).upper()
            else:
                return None
        except Exception as e:
            print(f"Error extracting hex from '{column_value}': {e}")
            return None

    def show_help(self):
        """Display help window with program usage instructions"""
        help_window = tk.Toplevel(self.root)
        help_window.title("VPW Analyzer Help")
        help_window.geometry("800x600")
        help_window.resizable(True, True)
        
        # Create scrollable text widget
        frame = tk.Frame(help_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(frame, wrap=tk.WORD, font=("Arial", 10))
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Help content
        help_text = """VPW Analyzer Help
==================

HOW TO USE THE PROGRAM
======================

OBD Device Serial Port Field:
• For serial communication: Enter the serial port path
  - Linux: /dev/ttyUSB0, /dev/ttyACM0, etc.
  - Windows: COM1, COM3, COM4, etc.
• For file analysis: Enter the full path to a VPW log file
  - Example: /home/user/vpw_log.txt
  - Example: C:\\Users\\User\\Documents\\vpw_log.txt
• Click "Read" to open the port/file and start parsing

Raw Line Input:
• Manually enter VPW messages for parsing
• Format: 3-byte header + data + checksum/CRC
• Example: 8C F1 10 11 80 24 5A
• Click "Parse" to process the message

Tips & Tricks:
==============
• Double-click any message in the Summary or Message History tables to automatically populate the Transmit Frame with that message's header and payload
• Use Ctrl+A in any text field to select all text
• The "Hide Module Heartbeats" option filters out routine heartbeat messages
• Adjust "Compare First # Bytes" to control how messages are grouped in the summary table

VPW Protocol Primer
===================

GM VPW Implementation Overview:
GM's VPW (Variable Pulse Width) implementation uses a 3-byte header structure that includes the target address and source address (the module that sent the message).

Addressing Modes:
• Physical Address: Used for node-to-node communication (e.g., scan tool reading codes from a specific module)
• Functional Address: Used for broadcast communication to multiple modules

Message Types:
The Mode column shows "F" for functional messages. Functional messages have several types:

Command vs Status IDs:
• Command IDs are always even numbers (e.g., $1A, $32, $48)
• Status IDs are always the command ID + 1 (e.g., $1B, $33, $49)
• Command = request/instruction, Status = response/confirmation

Extended Address Messages:
• "F Ext" in the Type column indicates Functional Extended Address
• Provides additional location detail to functional messages
• Examples: "front running lights only", "passenger door open"
• Always includes a second data byte for location information

Secondary IDs:
• First data byte of any functional message is the Secondary ID
• Provides "sub-fields" for the functional ID
• Example: Engine RPM functional ID $1B (status) has:
  - Secondary ID $02 = High resolution RPM
  - Secondary ID $20 = Target idle speed
  - Secondary ID $10 = Throttle position

Extended Address Details:
• If message type contains "F Ext", there will always be a second data byte
• This byte provides physical location details for the secondary ID
• Location byte varies depending on secondary ID and functional address used
• Additional data bytes may follow for actual measurements

Binary Flags:
• Some secondary IDs are On/Off or Enabled/Disabled flags
• Signaled by bit 7 (also called the Q-bit)of the secondary ID byte (first data byte)
• Q-bit = 1: On/Enabled, Q-bit = 0: Off/Disabled

Data Processing:
• Additional data (like percentage readings) comes after the secondary ID
• For F Ext messages: after secondary ID AND extended address
• For regular F messages: after secondary ID only
• PRD (Parameter Response Data) calculations convert raw bytes to meaningful values

Message Structure Examples:
==========================

Regular Functional Message:
Header: 8C F1 10
Data:   11 80 24 5A
• 8C = Priority/Header
• F1 = Target Address (Functional)
• 10 = Source Address (ECU)
• 11 = Secondary ID
• 80 = Data byte 1
• 24 = Data byte 2
• 5A = Checksum

Extended Functional Message:
Header: 8C F1 10
Data:   11 22 80 24 5A
• 8C = Priority/Header
• F1 = Target Address (Functional)
• 10 = Source Address (ECU)
• 11 = Secondary ID
• 22 = Extended Address (location detail)
• 80 = Data byte 1
• 24 = Data byte 2
• 5A = Checksum

For more detailed information about VPW protocol, refer to SAE J1850 and SAE J2178 standards.
"""
        
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)  # Make read-only
        
        # Add close button
        close_button = tk.Button(help_window, text="Close", command=help_window.destroy)
        close_button.pack(pady=10)

    def on_app_close(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            if (self.thread_reading):
                self.thread_reading.stop()
                self.thread_reading.join(3)
                if (self.thread_reading.is_alive()):
                    print("Error ending thread for app exit...")
            self.root.destroy()




if __name__ == "__main__" :
    app = Application(tk.Tk())
    app.root.wm_protocol("WM_DELETE_WINDOW", app.on_app_close)
    app.root.mainloop()

