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
from tkinter import messagebox
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
    Ext Addr is bit 4-0 of the second data byte (if applicable)
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
            0x01: ["VIN Dig 1", "", "", "", ""],
            0x02: ["VIN Digit 2-5", "", "", "", ""],
            0x03: ["VIN Digit 6-9", "", "", "", ""],
            0x04: ["VIN Digit 10-13", "", "", "", ""],
            0x05: ["VIN Digit 14-17", "", "", "", ""],
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
                modeOp = "Command Request"
            elif (zzwc == 0b0111):
                modeType = "F Req/Query"
                modeOp = "Function Query"
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
                modeOp = "Command Request"
            elif (zzwc == 0b1111):
                modeType = "F Ext Req/Query"
                modeOp = "Function Query"
                
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
    def get_description(func_address, msg):
        """Get description for functional messages based on secondary ID"""
        if (len(msg) == 0):
            return "No Message"
        
        payload = msg["message"][3:]
        if len(payload) == 0:
            return "No Payload"
        
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
                    return f"{secondary_info} ({msg['mode operation']})"
                elif isinstance(secondary_info, (list, set, tuple)) and len(secondary_info) > 0:
                    # Convert to list and get the first element (Name)
                    info_list = list(secondary_info)
                    base_description = info_list[0]  # Return the Name (first element)
                    
                    # Add Q-bit text if available
                    q_text = ""
                    if len(info_list) >= 3:  # Make sure we have at least 3 fields
                        if q_bit == 1 and len(info_list) > 1:
                            # Q-bit is 1, use 2nd field (index 1)
                            q_text = info_list[1]
                        elif q_bit == 0 and len(info_list) > 2:
                            # Q-bit is 0, use 3rd field (index 2)
                            q_text = info_list[2]
                    
                    # Check for external address lookup (4th field)
                    ext_address_text = ""
                    if len(info_list) >= 4 and len(payload) > 1:  # Make sure we have 4th field and second data byte
                        ext_addr_key = info_list[3]  # 4th field (index 3)
                        if ext_addr_key and ext_addr_key != "0" and ext_addr_key in VPW_frame.ext_addresses:
                            # Look up the second data byte in the ext_addresses
                            second_byte = payload[1]
                            if second_byte in VPW_frame.ext_addresses[ext_addr_key]:
                                ext_address_text = f" - {VPW_frame.ext_addresses[ext_addr_key][second_byte]}"
                    
                    # Combine all parts
                    result = base_description
                    if q_text:
                        result += f": {q_text}"
                    if ext_address_text:
                        result += ext_address_text
                    
                    # Add operation type at the end
                    result += f" ({msg['mode operation']})"
                    
                    return result
    
        #return f"Unknown SecID: {secondary_id:02X}"
        return f"({msg['mode operation']})"
        
    
        
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
            description = VPW_frame.get_description(target_addr, newMsg)
        else:
            if newMsg["message"][1] in VPW_frame.phys_addresses:
                taModule = str("${:02X}".format(newMsg["message"][1])+" "+VPW_frame.phys_addresses[newMsg["message"][1]])
            else:
                taModule = "${:02X}".format(newMsg["message"][1])
                
        if newMsg["message"][2] in VPW_frame.phys_addresses:
            saModule = str("${:02X}".format(newMsg["message"][2])+" "+VPW_frame.phys_addresses[newMsg["message"][2]])
        else:
            saModule = "${:02X}".format(newMsg["message"][2])
        
        # Append message to data frame (now includes description)
        self.messageHistory.append([len(self.messageHistory), newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:], inString, description])

        tempMsg = self.messageHistory[-1]
        
        # See if an existing message exists
        summaryInd = self.find_existing_summary(tempMsg)
        self.UIHook.new_message(tempMsg)
        self.UIHook.update_status_bar( len(self.messageHistory))
        
        # If hide heart beat is enabled, we'll just skip adding it to the summary altogether
        if (newMsg["heartbeat"] and self.UIHook.hideHeartbeats.get()):
            return
        
        if (summaryInd == -1):
            self.messageSummary.append([len(self.messageSummary), 0, tempMsg[0], newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:], description])
            
            self.UIHook.new_message_summary(self.messageSummary[-1])
        else:
            # Otherwise we need to update the record
            self.messageSummary[summaryInd][1] += 1
            self.messageSummary[summaryInd][2] = tempMsg[0]
            self.messageSummary[summaryInd][9] = tempMsg[7]
            self.messageSummary[summaryInd][10] = description  # Update description too
            
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
        self.summaryTree = ttk.Treeview(self.root, columns=( 'Last MID', '# Msgs', 'Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Description'))
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
        self.summaryTree.heading('#10', text='Description')
        
 
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
        self.summaryTree.column('#10', minwidth=50, width=300, stretch=tk.YES)
 
        self.summaryTree.grid(row=1, column=0, sticky='nsew')
        self.summaryTreeScroll.grid(row=1, column=1, sticky='nsw')
        
        
        
        
        
        ''' Message Tree '''
        self.messageTree_Label = tk.Label(self.root, text="Message history")
        self.messageTree_Label.grid(row=2, column=0,  sticky=tk.W)
        self.messageTree_checkbox = tk.Checkbutton(self.root, text="Lock to most recent", variable=self.messageTreeLock, onvalue=True, offvalue=False)
        self.messageTree_checkbox.grid(row=2,column=0, sticky=tk.E)
        
        # Set the treeview for the raw transaction table
        self.messageTree = ttk.Treeview(self.root, columns=('Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload', 'Description'))
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
        self.messageTree.heading('#8', text='Description')
        
 
        # Specify attributes of the columns (We want to stretch it!)
        self.messageTree.column('#0', minwidth=30, width=40, stretch=tk.YES)
        self.messageTree.column('#1', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#2', minwidth=40, width=40, stretch=tk.YES)
        self.messageTree.column('#3', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#4', minwidth=30, width=60, stretch=tk.YES)
        self.messageTree.column('#5', minwidth=30, width=170, stretch=tk.YES)
        self.messageTree.column('#6', minwidth=30, width=80, stretch=tk.YES)
        self.messageTree.column('#7', minwidth=50, width=200, stretch=tk.YES)
        self.messageTree.column('#8', minwidth=50, width=300, stretch=tk.YES)
 
        self.messageTree.grid(row=3, column=0, sticky='nsew')
        self.messageTreeScroll.grid(row=3, column=1, sticky='nsw')
        
        ''' Configuration Frame '''
        self.config_frame = tk.Frame(self.root, borderwidth = 1)
        self.config_frame.grid(row=1, column = 3, rowspan=1, sticky='nsew')
        self.config_frame.grid_rowconfigure(90, weight=1)
        
        # Define the different GUI widgets
        self.config_label = tk.Label(self.config_frame, text="OBD II Configuration")
        self.config_label.grid(row=0, column=0, columnspan=2, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=1, columnspan = 2, sticky='ew')
        self.serial_label = tk.Label(self.config_frame, text="OBD Device Serial Port")
        self.serial_port_entry = tk.Entry(self.config_frame)
        self.serial_label.grid(row=2, column=0, sticky=tk.W)
        self.serial_port_entry.grid(row=2, column=1)
        
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
        self.config_label.grid(row=4, column=0, columnspan=2, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=5, columnspan = 2, sticky='ew')
        
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
        
        self.copy_button = tk.Button(self.transmit_frame, text="Copy from selected")
        self.copy_button.grid(row=4, column=0, sticky='s')
        
        self.send_button = tk.Button(self.transmit_frame, text="Send")
        self.send_button.grid(row=4, column=1, sticky='s')
        
        config_sep = ttk.Separator(self.transmit_frame, orient='horizontal')
        config_sep.grid(row=5, columnspan = 2, sticky='ew')
        
        self.send_selected_button = tk.Button(self.transmit_frame, text="Send Selected Message")
        self.send_selected_button.grid(row=6, column=0, sticky='s')
        
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
    
    def insert_data(self):
        rawString = self.idnumber_entry.get()
        self.mm.new_message(rawString)
        
    def export_log(self):
        fexport = open("export.txt", "w")
        for line in self.mm.messageHistory:
            fexport.write(line[-1]+"\r\n")
        fexport.close()
        

    def new_message(self, newMsg):        
        # Print the message to the message history tree
        self.messageTree.insert('', 'end', iid=newMsg[0], text=str(newMsg[0]),
                             values=("{:02X}".format(newMsg[1]), newMsg[4], newMsg[5],
                             newMsg[6], newMsg[2], newMsg[3], str(" ".join(["{:02X}".format(x) for x in newMsg[7][:-1]])), newMsg[9]))

        # If the scroll lock is enabled, then scroll down
        if (self.messageTreeLock.get()):
            self.messageTree.yview_moveto(1)
            
        self.update_status_bar()
        
        
        
    def new_message_summary(self, newMsg):        
        # Print the message to the message history tree
        self.summaryTree.insert('', 'end', iid=newMsg[0], text=str(newMsg[0]),
                             values=(newMsg[0], 0, "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7],
                             newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]])), newMsg[10]))
        #self.sid = self.sid + 1
        
        
    def update_message_summary(self, index, newMsg):
        values = self.summaryTree.item(index)
        #print ("Updating UI: ", values, "and", newMsg)
        try:
            self.summaryTree.item(index, text=str(index),
                             values=(newMsg[2], newMsg[1], "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7], newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]])), newMsg[10]))
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

