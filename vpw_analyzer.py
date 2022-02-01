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
            print ("Opening serial port:",self.filename)
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
            if (len(self.sp.read_until(b'>')) == 0): raise Exception("Device did not respond to reset")
            self.sp.write(b'atz\r\n')   # Reset the device
            reset_response = self.sp.read_until(b'>')
            if (len(reset_response) == 0): raise Exception("Did not receieve any data from device. Wrong serial port?")
            if (b'OK' not in reset_response):
                # Seems we interrupted a command, let's try again
                self.sp.write(b'atz\r\n')   # Reset the device
                reset_response = self.sp.read_until(b'>')
                if (len(reset_response) == 0): raise Exception("Did not receieve any data from device. Wrong serial port?")
                if (b'OK' not in reset_response and reset_response[-1] != b'>'): raise Exception("Device did not acknowledge reset request")

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
    C is for command (request)
    S is for status (response)

    These are defined as well in SAE J2178-4
    '''
    func_addresses = {
        0x0B:"(C) Eng Air Intake",      0x0B:"(S) Eng Air Intake",
        0x12:"(C) Fuel",                0x13:"(S) Fuel",
        0x14:"(C) AC Clutch",           0x15:"(S) AC Clutch",
        0x1A:"(C) Engine RPM",          0x1B:"(S) Engine RPM",
        0x24:"(C) Wheels",              0x25:"(S) Wheels",
        0x28:"(C) Vehicle Speed",       0x29:"(S) Vehicle Speed",
        0x2A:"(C) Traction Control",    0x2B:"(S) Traction Control",
        0x32:"(C) Brakes",              0x33:"(S) Brakes",
        0x34:"(C) Steering",            0x35:"(S) Steering",
        0x3A:"(C) Trans",               0x3B:"(S) Trans",
        0x48:"(C) Eng Coolant",         0x49:"(S) Eng Coolant",
        0x4A:"(C) Eng Oil",             0x4B:"(S) Eng Oil",
        0x52:"(C) Engine Sys",          0x53:"(S) Engine Sys",
        0x58:"(C) Suspension",          0x59:"(S) Suspension",
        0x62:"(C) Cruise Control",      0x63:"(S) Cruise Control",
        0x72:"(C) Charging System",     0x73:"(S) Charging System",
        0x7A:"(C) Odometer",            0x7B:"(S) Odometer",
        0x82:"(C) Fuel System",         0x83:"(S) Fuel System",
        0x84:"(C) Vehicle Motion",      0x85:"(S) Vehicle Motion",
        0x86:"(C) Ign Switch",          0x87:"(S) Ign Switch",
        0x92:"(C) Veh Security",        0x93:"(S) Veh Security",
        0x96:"(C) Chimes",              0x97:"(S) Chimes",
        0xC6:"(C) Extern Access",       0xC7:"(S) Extern Access",
        0xCE:"(C) MFG Specific",        0xCF:"(S) MFG Specific",
        0xD2:"(C) Restraints",          0xD3:"(S) Restraints",
        0xDA:"(C) Exterior Lamps",      0xDB:"(S) Exterior Lamps",
        0xDE:"(C) Interior Lamps",      0xDF:"(S) Interior Lamps",
        0xE4:"(C) Tires",               0xE5:"(S) Tires",
        0xE6:"(C) Defrost",             0xE7:"(S) Defrost",
        0xEA:"(C) MFG Specific",        0xEB:"(S) MFG Specific",
        0xF2:"(C) Ext Environment",     0xF3:"(S) Ext Environment",
        0xFA:"(C) VIN",                 0xFB:"(S) VIN",
        0xFE:"(C) Network Control",     0xFF:"(S) Network Control"
    }
    
    '''
    Physical Module Addresses Used in GM VPW-based Vehicles.
    These came from C5 vehicles, but should be consistent across similar 1997-2004 era GM vehicles
    '''
    phys_addresses = {
        0x10:"ECU",
        0x28:"ABS",
        0x40:"BCM",
        0x58:"SRS",
        0x60:"Cluster",
        0x80:"Radio",
        0x99:"HVAC",
        0xA0:"LDCM",
        0xA1:"RDCM",
        0xA6:"SCM",
        0xB0:"Remotes",
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

        priority = byteArray[0] >> 5
        mode = 'F'
        modeType = "?"
        if byteArray[0] & 0x04:
            mode = 'P'
            modeType = (byteArray[0] & 0x0F) 
            if (modeType) == 0x0C:
                modeType = "N-N"
        
        if (byteArray[0] & 0x0F) == 0x08:
            modeType = "Func"
        elif (byteArray[0] & 0x0F) == 0x09:
            modeType = "Broadcast"
        elif (byteArray[0] & 0x0F) == 0x0A:
            modeType = "Query"
        elif (byteArray[0] & 0x0F) == 0x0B:
            modeType = "Read"
            
        if (byteArray[0] & 0x10) == 0x10:
            mode = "?H"
        if (byteArray[0] & 0x08) == 0x00:
            mode = "?IFR"
            
        # Check if is a heart beat
        isHeartBeat = False
        if (byteArray[1] == 0xFF or byteArray[1] == 0xFE):
            if (len(byteArray) == 5):
                if (byteArray[3] == 0x03):
                    isHeartBeat = True

        return {'priority': priority, 'mode': mode, 'mode type': modeType, 'message': byteArray, 'heartbeat': isHeartBeat}
        
    
        
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
        if (newMsg["mode"] == "F"):
            if newMsg["message"][1] in VPW_frame.func_addresses:
                taModule = str("${:02X}".format(newMsg["message"][1])+" "+VPW_frame.func_addresses[newMsg["message"][1]])
            else:
                taModule = "${:02X}".format(newMsg["message"][1])
        else:
            if newMsg["message"][1] in VPW_frame.phys_addresses:
                taModule = str("${:02X}".format(newMsg["message"][1])+" "+VPW_frame.phys_addresses[newMsg["message"][1]])
            else:
                taModule = "${:02X}".format(newMsg["message"][1])
                
        if newMsg["message"][2] in VPW_frame.phys_addresses:
            saModule = str("${:02X}".format(newMsg["message"][2])+" "+VPW_frame.phys_addresses[newMsg["message"][2]])
        else:
            saModule = "${:02X}".format(newMsg["message"][2])
        #Physical address
        # Append message to data frame
        self.messageHistory.append([len(self.messageHistory), newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:],inString])

        tempMsg = self.messageHistory[-1]
        
        # See if an existing message exists
        summaryInd = self.find_existing_summary(tempMsg)
        self.UIHook.new_message(tempMsg)
        self.UIHook.update_status_bar( len(self.messageHistory))
        
        
        
        # If hide heart beat is enabled, we'll just skip adding it to the summary altogether
        if (newMsg["heartbeat"] and self.UIHook.hideHeartbeats.get()):
            return
        
        if (summaryInd == -1):
            self.messageSummary.append([len(self.messageSummary), 0, tempMsg[0], newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:]])
            
            self.UIHook.new_message_summary(self.messageSummary[-1])
        else:
            # Otherwise we need to update the record
            self.messageSummary[summaryInd][1] += 1
            self.messageSummary[summaryInd][2] = tempMsg[0]
            self.messageSummary[summaryInd][9] = tempMsg[7]
            
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
    def __init__(self, gui, file_path):
        threading.Thread.__init__(self)
        self.gui = gui
        self.file_path = file_path
        self.stop_var = False
        self.obd = None
        
    def run(self):
        if (self.obd):
            self.obd.close()

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
                    continue
                #TODO: Probably should use a queue instead of calling another thread's function...
                self.gui.mm.new_message(line)
            except:
                print ("Exception in file reading thread")
                break
        
        self.obd.close()

    def stop(self):
        self.stop_var = True
    
'''
Main application class that handles the GUI
'''
class Application(tk.Frame):
    def __init__(self, root):
        self.root = root
        self.thread_reading = None
        self.initialize_user_interface()
        self.update_status_bar(False)
        self.mm = MessageManager(self)
 
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
        self.summaryTree = ttk.Treeview(self.root, columns=( 'Last MID', '# Msgs', 'Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload'))
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
 
        self.summaryTree.grid(row=1, column=0, sticky='nsew')
        self.summaryTreeScroll.grid(row=1, column=1, sticky='nsw')
        
        
        
        
        
        ''' Message Tree '''
        self.messageTree_Label = tk.Label(self.root, text="Message history")
        self.messageTree_Label.grid(row=2, column=0,  sticky=tk.W)
        self.messageTree_checkbox = tk.Checkbutton(self.root, text="Lock to most recent", variable=self.messageTreeLock, onvalue=True, offvalue=False)
        self.messageTree_checkbox.grid(row=2,column=0, sticky=tk.E)
        
        # Set the treeview for the raw transaction table
        self.messageTree = ttk.Treeview(self.root, columns=('Hdr', 'Prio', 'Mode', 'Type', 'TA', 'SA', 'Payload'))
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
        
 
        # Specify attributes of the columns (We want to stretch it!)
        self.messageTree.column('#0', minwidth=30, width=40, stretch=tk.YES)
        self.messageTree.column('#1', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#2', minwidth=40, width=40, stretch=tk.YES)
        self.messageTree.column('#3', minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column('#4', minwidth=30, width=60, stretch=tk.YES)
        self.messageTree.column('#5', minwidth=30, width=170, stretch=tk.YES)
        self.messageTree.column('#6', minwidth=30, width=80, stretch=tk.YES)
        self.messageTree.column('#7', minwidth=50, width=200, stretch=tk.YES)
 
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
 
        self.idnumber_label = tk.Label(self.config_frame, text="Raw Line")
        self.idnumber_entry = tk.Entry(self.config_frame)
        self.idnumber_label.grid(row=3, column=0, sticky=tk.W)
        self.idnumber_entry.grid(row=3, column=1)
 
 
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
        
        self.payload_label = tk.Label(self.transmit_frame, text="Payload")
        self.payload_label.grid(row=3, column=0)
        self.payload_entry = tk.Entry(self.transmit_frame)
        self.payload_entry.grid(row=3, column=1)
        self.payload_entry.insert(0, "24 00")
        
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
                             newMsg[6], newMsg[2], newMsg[3], str(" ".join(["{:02X}".format(x) for x in newMsg[7][:-1]]))))

        # If the scroll lock is enabled, then scroll down
        if (self.messageTreeLock.get()):
            self.messageTree.yview_moveto(1)
            
        self.update_status_bar()
        
        
        
    def new_message_summary(self, newMsg):        
        # Print the message to the message history tree
        self.summaryTree.insert('', 'end', iid=newMsg[0], text=str(newMsg[0]),
                             values=(newMsg[0], 0, "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7],
                             newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]]))))
        #self.sid = self.sid + 1
        
        
    def update_message_summary(self, index, newMsg):
        values = self.summaryTree.item(index)
        #print ("Updating UI: ", values, "and", newMsg)
        try:
            self.summaryTree.item(index, text=str(index),
                             values=(newMsg[2], newMsg[1], "{:02X}".format(newMsg[3]), newMsg[6], newMsg[7], newMsg[8], newMsg[4], newMsg[5], str(" ".join(["{:02X}".format(x) for x in newMsg[9][:-1]]))))
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

        self.thread_reading = ThreadedTask(self, file_path)
        self.thread_reading.start()

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

