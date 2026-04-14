'''
VPW Analyzer
By Jonathan Valdez

Description: This is a utility that parses incoming messages from a VPW interface
    into a more human-readable format. The bottom box shows each message that was
    received in order. The top box shows unique messages that were received.
    It connects to an ELM327 like device via a serial port. If on Windows, type
    the COM port number into the 'OBD Device Port' and press 'Read/Open'. If on Unix
    based system, type in the full path (/dev/serialTTY) and press 'Read/Open'.

Version 0.5 - Apr 11, 2026
Changes
    - Added support for OBDX Pro VT
    - Added support for VPW log files
    - Added support time stamps
    - Added support transmitting for OBDX Pro VT
'''
from logging import exception
from enum import Enum
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from message_queue_window import (
    MessageQueueStore,
    description_from_tree_values,
    destroy_message_queue_window_if_any,
    open_or_raise_message_queue_window,
)
import tkinter.ttk as ttk
import queue
import sys
import threading
from collections import deque
import time
import serial
import re
import string


# Short read timeout while probing ELM prompts (adapter stuck in DVI won't send '>')
OBD_SERIAL_PROBE_TIMEOUT = 0.4
OBD_SERIAL_RUNTIME_TIMEOUT = 3.0


def _dvi_checksum(body_without_chk):
    """OBDX DVI checksum: bitwise NOT of (sum of preceding bytes mod 256)."""
    return ((~sum(body_without_chk)) & 0xFF)


def _dvi_pack(cmd, data):
    """Build a normal DVI frame: cmd, len(data), data..., checksum (cmd 0x08–0x11 style)."""
    data = bytes(data)
    if len(data) > 255:
        raise ValueError("payload too long for normal DVI frame; use large-frame command")
    body = bytes([cmd, len(data)]) + data
    return body + bytes([_dvi_checksum(body)])


def _dvi_reboot_to_boot_frame():
    """§3.10.1 Software reboot — returns adapter to ELM default after boot."""
    return bytes([0x25, 0x00, _dvi_checksum([0x25, 0x00])])


def _vpw_crc8_sae_j1850(body: bytes) -> int:
    """
    One-byte VPW frame CRC (CRC-8/SAE-J1850 style: poly 0x1D, init 0xFF, xorout 0xFF, MSB-first).
    ``body`` is the full frame without the CRC byte (header + payload).
    """
    crc = 0xFF
    for b in body:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x1D) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc ^ 0xFF


def _vpw_frame_append_crc_if_missing(frame: bytes) -> bytes:
    """
    If the last byte is already a valid VPW CRC for the preceding bytes, return ``frame`` unchanged.
    Otherwise append the CRC for the whole frame (OBDX DVI passive RX / older exports omit bus CRC).
    """
    frame = bytes(frame)
    if len(frame) < 3:
        return frame
    if len(frame) >= 4 and _vpw_crc8_sae_j1850(frame[:-1]) == frame[-1]:
        return frame
    return frame + bytes([_vpw_crc8_sae_j1850(frame)])


def _vpw_hex_line_append_crc_if_missing(hex_line: str) -> str:
    """Normalize a VPW hex text line so it includes a trailing CRC when absent (log import / Parse)."""
    s = hex_line.strip()
    if not s or not VPW_frame.is_valid(s):
        return hex_line
    try:
        raw = bytes.fromhex(s.replace(" ", ""))
    except ValueError:
        return hex_line
    if len(raw) < 3:
        return hex_line
    fixed = _vpw_frame_append_crc_if_missing(raw)
    if fixed == raw:
        return hex_line
    return " ".join(f"{b:02X}" for b in fixed)


# Bytes shown as characters in "try decode ASCII" payload view (letters, digits, punctuation, space).
_ASCII_PAYLOAD_VIEW_BYTES = frozenset(
    (string.ascii_letters + string.digits + string.punctuation + " ").encode("latin-1")
)


def _vpw_payload_body_bytes(payload_bytes):
    """Payload bytes shown in the Payload column (strip trailing CRC when multi-byte)."""
    if not payload_bytes:
        return b""
    pb = bytes(payload_bytes)
    if len(pb) == 1:
        return pb
    return pb[:-1]


def _vpw_payload_hex_for_display(payload_bytes):
    """Format payload for Treeview; strip trailing CRC when present (ELM). DVI often has no CRC."""
    body = _vpw_payload_body_bytes(payload_bytes)
    if not body:
        return ""
    return " ".join("{:02X}".format(x) for x in body)


def _vpw_payload_hex_with_ascii_bracket(payload_bytes):
    """Space-separated hex plus a bracketed ASCII run (~ for non-printable-set bytes)."""
    hx = _vpw_payload_hex_for_display(payload_bytes)
    body = _vpw_payload_body_bytes(payload_bytes)
    if not body:
        return hx
    chars = []
    for b in body:
        chars.append(chr(b) if b in _ASCII_PAYLOAD_VIEW_BYTES else "~")
    bracket = "[" + "".join(chars) + "]"
    return f"{hx} {bracket}" if hx else bracket


def _vpw_payload_column_text(payload_bytes, try_ascii):
    if try_ascii:
        return _vpw_payload_hex_with_ascii_bracket(payload_bytes)
    return _vpw_payload_hex_for_display(payload_bytes)


def _vpw_payload_hex_for_transmit(payload_bytes):
    """Space-separated hex for transmit / queue (same body as Payload column, never ASCII)."""
    return _vpw_payload_hex_for_display(payload_bytes)


# Datalog lines may start with relative receive time in seconds (exactly three fractional digits).
_VPW_LOG_TIMESTAMP_PREFIX_RE = re.compile(r"^(\d+\.\d{3})\s+(.+)$")


def _split_vpw_logfile_line(line):
    """
    Parse optional leading timestamp from a saved log line.
    Returns (hex_line, relative_seconds_or_none). Timestamp must use exactly three decimal places.
    """
    s = (line or "").strip()
    if not s:
        return ("", None)
    m = _VPW_LOG_TIMESTAMP_PREFIX_RE.match(s)
    if m:
        return (m.group(2).strip(), float(m.group(1)))
    return (s, None)


def _format_vpw_export_timestamp(seconds):
    """Export / display relative time with exactly three decimal places."""
    return f"{float(seconds):.3f}"


# Help text for the application
HELP_TEXT = """VPW Analyzer Help
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
• Click "Read/Open" to open the port or log file and start parsing; use "Close port" to stop the reader thread and close the serial device cleanly
• From a terminal you can run: python vpw_analyzer.py <path> — the path is filled in and Read/Open runs automatically

Raw Line Input:
• Manually enter VPW messages for parsing
• Format: 3-byte header + data + checksum/CRC (if the CRC byte is missing—common with OBDX DVI exports—the program adds SAE J1850 CRC-8 before parsing, same as live DVI capture)
• Example: 8C F1 10 11 80 24 5A
• Click "Parse" to process the message

Tips & Tricks:
==============
• Double-click any message in the Summary or Message History tables to automatically populate the Transmit Frame with that message's header and payload
• Use Ctrl+A in any text field to select all text
• "Hide module heartbeats from summary table" (on by default) filters routine heartbeats out of the summary only (they still appear in message history unless the next option is on)
• "Hide module heartbeats from everything" (on by default) also omits them from message history and export
• Adjust "Compare First # Bytes" to control how messages are grouped in the summary table
• Click once on a row in Summary or Message history to mark it (highlight) for "Send Selected Message"; double-click still fills the transmit fields only
• With focus in Summary or Message history, Space triggers Send Selected Message (same as the button)
• Right-click a row in Summary or Message history: Add to queue (new queue or append to an existing one). Open Message queues from the transmit panel to reorder messages, double-click Header/Payload/Description to edit (Enter saves, Esc cancels), Export/Import JSON, or send an entire queue in order; use Load into transmit to copy the selected row to the transmit fields
• "Show transmitted frames in message history" is on by default; turn it off if you do not want each successful send appended as a green-tagged row with a [TX] description prefix
• "Try to decode ASCII in payload column" (under View Settings) keeps the normal space-separated hex and appends a bracketed run (e.g. [A~b]) with one character per byte for letters, digits, punctuation, and space, or ~ otherwise; transmit, Send Selected, and Add to queue still use raw hex from the stored frame only
• Live serial capture timestamps each frame when it is read from the adapter (ms internally, shown as seconds). Log files may optionally begin each line with a relative time in the form ``0.000`` (three decimal places), a space, then the hex frame; Read/Open accepts both formats
• Export Logs opens a dialog: you can include those timestamps at the start of each line when the history has capture times (optional per-line if some rows have no time)

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

'''
PRD (Parameter Response Data) class contains all data conversion methods
for VPW message payloads according to SAE J2178 standards.
'''
class PRD:
    """Parameter Response Data conversion methods for VPW messages"""
    
    # UNM (Unsigned Numeric) 8-bit methods
    @staticmethod
    def unm_08_15(payload):
        """Convert 0-255 byte to 1/100 L per UNM-08-15"""
        return (payload[0]) / 100 if len(payload) > 0 else 0

    @staticmethod
    def unm_08_21(payload):
        """Convert 0-255 byte to 1/6 per UNM-08-21"""
        return (payload[0]) / 16 if len(payload) > 0 else 0

    @staticmethod
    def unm_08_32(payload):
        """Convert 0-255 byte to 1/16 per UNM-08-32"""
        return (payload[0]) / 16 if len(payload) > 0 else 0
    
    @staticmethod
    def unm_08_41(payload):
        """Convert 0-255 byte to 1/10 per UNM-08-41"""
        return (payload[0]) / 10 if len(payload) > 0 else 0

    @staticmethod
    def unm_08_61(payload):
        """Convert 0-255 byte to 0-100% per UNM-08-61"""
        return (payload[0] * 100) / 255 if len(payload) > 0 else 0

    @staticmethod
    def unm_08_71(payload):
        """Convert 0-255 byte to 0-100% per UNM-08-71"""
        return (payload[0] / 2) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_73(payload):
        """Convert 0-255 byte to -40 to 87.5°C per UNM-08-73"""
        return (payload[0] / 2) - 40 if len(payload) > 0 else 0
    
    @staticmethod
    def unm_08_101(payload):
        """Convert byte to 0 to 255 per UNM-08-101"""
        return (payload[0]) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_102(payload):
        """Convert byte to temperature in Celsius (-40 to 215°C) per UNM-08-102"""
        return payload[0] - 40 if len(payload) > 0 else 0

    @staticmethod
    def unm_08_125(payload):
        """Convert byte to 0 to 637 per UNM-08-125"""
        return (payload[0] * 5) / 2  if len(payload) > 0 else 0

    @staticmethod
    def unm_08_131(payload):
        """Convert byte to 0 to 765 per UNM-08-131"""
        return (payload[0] * 3) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_141(payload):
        """Convert byte to 0 to 1048 per UNM-08-141"""
        return (payload[0] * 4) if len(payload) > 0 else 0
    
    @staticmethod
    def unm_08_151(payload):
        """Convert byte to 0 to 2048 per UNM-08-151"""
        return (payload[0] * 8) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_155(payload):
        """Convert byte to 0 to 2550 g per UNM-08-155"""
        return (payload[0] * 10) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_159(payload):
        """Convert byte to 0 to 3570 per UNM-08-159"""
        return (payload[0] * 14) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_161(payload):
        """Convert byte to 0 to 4096 per UNM-08-161"""
        return (payload[0] * 16) if len(payload) > 0 else 0

    @staticmethod
    def unm_08_171(payload):
        """Convert byte to 0 to 8160 per UNM-08-171"""
        return (payload[0] * 32) if len(payload) > 0 else 0

    # SED (State Encoded Data) 8-bit methods
    @staticmethod
    def sed_08_7(payload):
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
    def sed_08_4(payload):
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
    def sed_08_5(payload):
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
    def sed_08_6(payload):
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

    # UNM (Unsigned Numeric) 16-bit methods

    @staticmethod
    def unm_16_5(payload):
        """Convert byte to 0 to 512 per UNM-16-5"""
        return (payload[0] << 8 | payload[1]) / 128 if len(payload) > 1 else None

    @staticmethod
    def unm_16_11(payload):
        """Convert byte to 0 to 655.35 per UNM-16-11"""
        return (payload[0] << 8 | payload[1]) / 100 if len(payload) > 1 else None

    @staticmethod
    def unm_16_31(payload):
        """Convert byte to 0 to 61383 per UNM-16-31"""
        return (payload[0] << 8 | payload[1]) / 4 if len(payload) > 1 else None

    @staticmethod
    def unm_24_11(payload):
        """Convert byte to 0 to 1677721.6 per UNM-24-11"""
        return ((payload[0] << 16 | payload[1] << 8 | payload[2]) / 10) if len(payload) > 2 else None

    @staticmethod
    def unm_24_41(payload):
        """Convert byte to 0 to 262143.98 per UNM-24-41"""
        return ((payload[0] << 16 | payload[1] << 8 | payload[2]) / 64) if len(payload) > 2 else None

    @staticmethod
    def unm_32_31(payload):
        """Convert byte to 0 to 4194303.75 per UNM-32-31"""
        return ((payload[0] << 24 | payload[1] << 16 | payload[2] << 8 | payload[3]) / 64) if len(payload) > 3 else None

    # ASC (ASCII) methods
    @staticmethod
    def asc_32_1(payload):
        """Convert bytes to ASCII string per ASC-32-1"""
        return "".join(chr(b) for b in payload[0:4]) if len(payload) > 3 else None   

    # PKT (Packet) methods
    @staticmethod
    def pkt_32_2(payload):
        """Convert bytes to ASCII string per PKT-32-2"""
        return chr(payload[3]) if len(payload) > 3 else None
    
    @staticmethod
    def dsp_c5_messages(payload):
        """Convert bytes to ASCII string per DSP-C5-Messages"""
        if (len(payload) < 1):
            return None
        if (payload[0] == 0x08) or (payload[0] == 0x01):
            return "(Blinking)"
        elif (payload[0] == 0x20) or (payload[0] == 0x40):
            return "(Solid)"
        return None


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
        self.dvi_mode = False
        self._dvi_rx_buffer = bytearray()
        self._dvi_pending_lines = []
        self._sp_lock = threading.RLock()
        # Monotonic clock value when VPW passive monitoring began (ATMA / DVI network on); used for RX timestamps.
        self._vpw_capture_t0 = None
        
        # There is probably a better way to determine if something is a serial device or not.
        if filename.lower().startswith("com") or filename.startswith("/dev"):
            self.serial = True
        

    def __del__ (self):
        self.close()

    def _vpw_bytes_to_hex_line(self, body, append_vpw_crc=False):
        """Format raw VPW frame bytes as hex. If ``append_vpw_crc``, add SAE J1850 CRC when DVI omitted it."""
        b = bytes(body)
        if append_vpw_crc:
            b = _vpw_frame_append_crc_if_missing(b)
        return " ".join(f"{b:02X}" for b in b)

    def _dvi_try_pop_frame(self):
        """If a complete valid DVI frame is at the front of the buffer, consume and return (cmd, payload)."""
        buf = self._dvi_rx_buffer
        if len(buf) < 3:
            return None
        cmd = buf[0]
        if cmd == 0x7F:
            dlen = buf[1]
            tot = 2 + dlen + 1
            if len(buf) < tot:
                return None
            frame = bytes(buf[:tot])
            del buf[:tot]
            if frame[-1] != _dvi_checksum(frame[:-1]):
                return None
            return (0x7F, frame[2:-1])
        if cmd == 0x09:
            if len(buf) < 5:
                return None
            dlen = (buf[1] << 8) | buf[2]
            tot = 1 + 2 + dlen + 1
            if len(buf) < tot:
                return None
            frame = bytes(buf[:tot])
            del buf[:tot]
            if frame[-1] != _dvi_checksum(frame[:-1]):
                return None
            return (0x09, frame[3:-1])
        if cmd == 0x08:
            dlen = buf[1]
            tot = 2 + dlen + 1
            if len(buf) < tot:
                return None
            frame = bytes(buf[:tot])
            del buf[:tot]
            if frame[-1] != _dvi_checksum(frame[:-1]):
                return None
            return (0x08, frame[2:-1])
        dlen = buf[1]
        tot = 2 + dlen + 1
        if len(buf) < tot:
            return None
        frame = bytes(buf[:tot])
        del buf[:tot]
        if frame[-1] != _dvi_checksum(frame[:-1]):
            return None
        return (cmd, frame[2:-1])

    def _dvi_feed(self):
        """Non-blocking read of any waiting serial bytes into the DVI buffer."""
        n = self.sp.in_waiting
        if n:
            self._dvi_rx_buffer.extend(self.sp.read(n))

    def _dvi_transact(self, cmd, data, timeout=3.0):
        """Send one DVI command and wait for response cmd+0x10 (or raise on 7F / timeout)."""
        pkt = _dvi_pack(cmd, data)
        self.sp.write(pkt)
        end = time.perf_counter() + timeout
        while time.perf_counter() < end:
            self._dvi_feed()
            while True:
                popped = self._dvi_try_pop_frame()
                if popped is None:
                    break
                rcmd, payload = popped
                if rcmd == 0x7F:
                    raise Exception(
                        f"OBDX DVI fault (request cmd 0x{cmd:02X}): payload {payload.hex()} "
                        "(0x7F = device rejected the command; often busy or not ready right after DX DP 1)"
                    )
                if rcmd in (0x08, 0x09):
                    self._dvi_pending_lines.append(self._vpw_bytes_to_hex_line(payload, append_vpw_crc=True))
                    continue
                if rcmd == cmd + 0x10:
                    return payload
            time.sleep(0.002)
        raise Exception("OBDX DVI command timeout")

    def _dvi_transact_setup_retry(self, cmd, data, timeout=3.0, max_attempts=4):
        """
        Send a DVI command during VPW monitor setup, retrying on transient 0x7F faults or timeouts.
        USB / firmware sometimes NAKs the first 0x24/0x31 sequence right after ``DX DP 1``.
        """
        delays = (0.08, 0.15, 0.28)
        for attempt in range(max_attempts):
            try:
                return self._dvi_transact(cmd, data, timeout=timeout)
            except Exception as e:
                es = str(e)
                retryable = "OBDX DVI fault" in es or "OBDX DVI command timeout" in es
                if not retryable or attempt >= max_attempts - 1:
                    raise
                if attempt < len(delays):
                    time.sleep(delays[attempt])
                else:
                    time.sleep(0.35)
                self.sp.reset_input_buffer()
                self._dvi_rx_buffer.clear()
                self._dvi_pending_lines.clear()

    def _open_obdx_dvi_vp_monitor(self):
        """Switch to DVI and enable VPW passive monitoring (OBDX Pro reference manual §3)."""
        self.sp.write(b"DX DP 1\r\n")
        rsp = self.sp.read_until(b">")
        if len(rsp) == 0 or b"OK" not in rsp:
            raise Exception("OBDX did not accept DX DP 1 (switch to DVI)")
        self.dvi_mode = True
        self._dvi_rx_buffer.clear()
        self._dvi_pending_lines.clear()
        self.sp.reset_input_buffer()
        time.sleep(0.06)
        # Timestamp off (default off; explicit), VPW protocol, network on — order per manual
        # §3.9.3: 24 02 03 NN — NN=00 timestamp off (explicit; default is off)
        self._dvi_transact_setup_retry(0x24, [0x03, 0x00])
        # §3.11: "31 02 01 XX" = len 0x02, payload 0x01 (sub) + XX (VPW = 0x01)
        self._dvi_transact_setup_retry(0x31, [0x01, 0x01])
        # §3.11.8: include VPW bus CRC in frames to the host (default OFF). Without it, the last bus
        # byte can equal the DVI serial checksum and the tool may drop or mis-frame that byte; with
        # CRC present, length is unambiguous. Firmware may then use §3.4 large receive (0x09) instead
        # of §3.3 normal (0x08); both are parsed in _dvi_try_pop_frame.
        self._dvi_transact_setup_retry(0x33, [0x08, 0x01])
        # "31 02 02 XX" = len 0x02, payload 0x02 (sub) + XX (network on = 0x01)
        self._dvi_transact_setup_retry(0x31, [0x02, 0x01])
        self._vpw_capture_t0 = time.perf_counter()

    def _recover_from_obdx_dvi_mode(self):
        """
        Prior exit in DVI leaves the tool speaking binary; ATZ is then parsed as garbage (7F...).
        Try DVI 'change API to ELM' (manual §3.11.3), then software reboot if needed.
        """
        self.sp.reset_input_buffer()
        self.sp.write(_dvi_pack(0x31, [0x06, 0x00]))
        time.sleep(0.35)
        self.sp.reset_input_buffer()
        self.sp.write(b"\r")
        r = self.sp.read_until(b">")
        if b">" in r:
            return
        print("OBDX: ELM API switch not detected; sending DVI software reboot (0x25)...")
        self.sp.reset_input_buffer()
        self.sp.write(_dvi_reboot_to_boot_frame())
        time.sleep(2.2)
        self.sp.reset_input_buffer()
        self.sp.write(b"\r")
        self.sp.read_until(b">")

    def _open_elm_vp_monitor(self):
        self.sp.write(b'atsp2\r\n')
        if (len(self.sp.read_until(b'>')) == 0):
            raise Exception("Device did not accept configuration")
        self.sp.write(b'ath1\r\n')
        if (len(self.sp.read_until(b'>')) == 0):
            raise Exception("Device did not accept configuration")
        self.sp.write(b'atma\r\n')
        if (len(self.sp.read_until(b'\r\n')) == 0):
            raise Exception("Device did not enter atma mode")
        self._vpw_capture_t0 = time.perf_counter()

    def _vpw_rx_timestamp_rel(self):
        """Seconds since passive VPW capture started, or None if capture not armed."""
        t0 = self._vpw_capture_t0
        if t0 is None:
            return None
        return time.perf_counter() - t0

    def reset_vpw_capture_epoch(self):
        """Restart relative RX timestamps from now (live serial only). Used when clearing message logs."""
        if self.serial:
            self._vpw_capture_t0 = time.perf_counter()

    def open(self, force_elm_protocol=False):
    
        if (self.serial):
            print ("Opening serial port:", self.filename)
        else:
            print ("Opening file:", self.filename)


        if (self.serial):
            if self.sp:
                self.sp.close()

            self.sp = serial.Serial(timeout=OBD_SERIAL_PROBE_TIMEOUT)
            self.sp.port = self.filename
            self.sp.open()
            
            if (not self.sp.is_open):
                raise Exception("Unable to open serial port")
                
            
            # Configure the modem (must be ELM text mode; if last session used DVI, recover first)
            self.sp.reset_input_buffer()
            self.sp.write(b'\r')
            wake = self.sp.read_until(b'>')
            if len(wake) == 0:
                self._recover_from_obdx_dvi_mode()
                self.sp.write(b'\r')
                wake = self.sp.read_until(b'>')
            if len(wake) == 0:
                raise Exception("No data received. Not connected/wrong serial port?")

            reset_ok = False
            for attempt in range(3):
                self.sp.write(b'atz\r\n')
                reset_response = self.sp.read_until(b'>')
                if len(reset_response) == 0:
                    if attempt < 2:
                        self._recover_from_obdx_dvi_mode()
                        continue
                    raise Exception("No data received after ATZ. Wrong serial port?")
                if b'OK' in reset_response and reset_response.rstrip().endswith(b'>'):
                    reset_ok = True
                    break
                if attempt < 2:
                    print("Unexpected ATZ response (adapter may be stuck in DVI); recovering...")
                    self._recover_from_obdx_dvi_mode()
                    continue
                raise Exception(
                    "Unexpected reset response after ATZ (expected OK and '>'). Raw: %r"
                    % (reset_response,)
                )
            if not reset_ok:
                raise Exception("Device did not accept ATZ reset")

            self.sp.write(b'atz\r\n')
            if len(self.sp.read_until(b'>')) == 0:
                raise Exception("Device did not respond to final reset")
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

            # Prefer OBDX when DX I responds — STN may also answer STI without '?'
            if ("?" not in self.dev_dxi_string):
                self.dev_type = "OBDX"
                self.dev_string = self.dev_dxi_string
            elif ("?" not in self.dev_sti_string):
                self.dev_type = "STN"
                self.dev_string = self.dev_sti_string
            else:
                self.dev_type = "ELM"
                self.dev_string = self.dev_ati_string

            print("Detected device was a",self.dev_type,"with a version string of:",self.dev_string)

            if self.dev_type == "OBDX":
                if force_elm_protocol:
                    print("OBDX: forcing ELM/AT passive monitor (skipping DVI).")
                    self._open_elm_vp_monitor()
                else:
                    self._open_obdx_dvi_vp_monitor()
            else:
                self._open_elm_vp_monitor()
            self.sp.timeout = OBD_SERIAL_RUNTIME_TIMEOUT
            print("Connected")
        else:
            self.fd = open(self.filename, 'r')
    
    def close(self):
        if self.serial:
            if self.sp.is_open:
                with self._sp_lock:
                    if self.dvi_mode:
                        try:
                            self.sp.reset_input_buffer()
                            # §3.11.3 — return to ELM so the next open() can use ATZ / DX DP 1
                            self.sp.write(_dvi_pack(0x31, [0x06, 0x00]))
                            time.sleep(0.2)
                        except Exception:
                            pass
                        self.dvi_mode = False
                    else:
                        self.sp.write(b'a\r\n')
                        time.sleep(1)
                    self.sp.close()
        else:
            self.fd.close()

    def read(self):
        """
        Returns ``(line, recv_rel_sec)``.
        ``line`` is a VPW hex line (often newline-terminated) or ``""`` at EOF / idle.
        ``recv_rel_sec`` is seconds since VPW capture started on serial, from the log prefix when replaying a file, else None.
        """
        if self.serial:
            with self._sp_lock:
                if self.dvi_mode:
                    if self._dvi_pending_lines:
                        return (self._dvi_pending_lines.pop(0) + "\n", self._vpw_rx_timestamp_rel())
                    end = time.perf_counter() + (self.sp.timeout or 3.0)
                    while time.perf_counter() < end:
                        self._dvi_feed()
                        while True:
                            popped = self._dvi_try_pop_frame()
                            if popped is None:
                                break
                            rcmd, payload = popped
                            if rcmd == 0x7F:
                                print("OBDX DVI bus fault:", payload.hex())
                                continue
                            if rcmd in (0x08, 0x09):
                                return (
                                    self._vpw_bytes_to_hex_line(payload, append_vpw_crc=True) + "\n",
                                    self._vpw_rx_timestamp_rel(),
                                )
                            if rcmd in (0x20, 0x21):
                                continue
                            print("OBDX DVI unsolicited frame cmd=%02X: %s" % (rcmd, payload.hex()))
                        time.sleep(0.002)
                    return ("", None)
                ln = self.sp.readline().decode("utf-8")
                if not ln:
                    return ("", None)
                return (ln, self._vpw_rx_timestamp_rel())
        else:
            raw = self.fd.readline()
            if raw == "":
                return ("", None)
            if isinstance(raw, bytes):
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            else:
                text = raw.rstrip("\r\n")
            hex_part, ts = _split_vpw_logfile_line(text)
            if not hex_part:
                return ("\n", None)
            return (hex_part + "\n", ts)

    def send_message(self, header, payload):
        """Send a VPW frame. OBDX DVI: 0x10/0x11 while monitoring. ELM/STN: exit ATMA, AT SH, send, AT MA."""
        if not self.serial or not self.sp.is_open:
            return False
        with self._sp_lock:
            try:
                hdr = bytes.fromhex(header.replace(" ", ""))
                pl = bytes.fromhex(payload.replace(" ", ""))
                full = hdr + pl
            except ValueError:
                return False
            if self.dvi_mode:
                return self._dvi_send_message(full)
            return self._elm_send_message(header, payload)

    def _elm_send_message(self, header, payload):
        """ELM327-style: break ATMA, set header, send hex payload, resume monitor."""
        try:
            h = "".join(header.split())
            if len(h) % 2 != 0 or not h:
                return False
            spaced = " ".join(h[i : i + 2].upper() for i in range(0, len(h), 2))
            pls = "".join(payload.split())
            if len(pls) % 2 != 0:
                return False
            self.sp.write(b"\r")
            time.sleep(0.08)
            n = self.sp.in_waiting
            if n:
                self.sp.read(n)
            self.sp.write(f"at sh {spaced}\r\n".encode())
            if len(self.sp.read_until(b">")) == 0:
                return False
            self.sp.write(f"{pls}\r\n".encode())
            if len(self.sp.read_until(b">")) == 0:
                return False
            self.sp.write(b"atma\r\n")
            if len(self.sp.read_until(b"\r\n")) == 0:
                if len(self.sp.read_until(b">")) == 0:
                    return False
            return True
        except Exception as e:
            print(f"ELM send_message: {e}")
            return False

    def _dvi_send_message(self, full_frame):
        """Send-to-network (manual §3.6/3.7). Caller must hold self._sp_lock."""
        try:
            if len(full_frame) > 255:
                body = bytes([0x11]) + len(full_frame).to_bytes(2, "big") + full_frame
                pkt = body + bytes([_dvi_checksum(body)])
            else:
                pkt = _dvi_pack(0x10, full_frame)
            self.sp.write(pkt)
            end = time.perf_counter() + 3.0
            while time.perf_counter() < end:
                self._dvi_feed()
                while True:
                    popped = self._dvi_try_pop_frame()
                    if popped is None:
                        break
                    rcmd, body = popped
                    if rcmd in (0x08, 0x09):
                        self._dvi_pending_lines.append(self._vpw_bytes_to_hex_line(body, append_vpw_crc=True))
                        continue
                    if rcmd == 0x7F:
                        print("OBDX DVI send fault:", body.hex())
                        return False
                    if rcmd in (0x20, 0x21):
                        return True
                    # Other DVI responses (e.g. config ack) — ignore while waiting for 20/21
                    continue
                time.sleep(0.002)
            return False
        except Exception as e:
            print(f"DVI send_message: {e}")
            return False
        
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
        0xEA:"Display Commands",
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

    # Custom functions can still be defined inline if needed
    # PRN can have inline definitions with a lambda function ["unit", lambda payload: custom_calculation(payload)],
    # example: ["unit", lambda payload: (payload[0] * 1) / 2 if len(payload) > 0 else 0],
    '''
    secondary_ids = {
        0x12: {  # Throttle
            0x01: ["Sensor 1 Position", "", "", "", ["%", PRD.unm_08_61]],
            0x02: ["Sensor 2 Position", "", "", "", ["%", PRD.unm_08_61]],
            0x03: ["Sensor 3 Position", "", "", "", ["%", PRD.unm_08_61]],
            0x10: ["Throttle Kicker", "E", "D", "", None],
            0x11: ["Throttle Position", "", "", "", ["%", PRD.unm_08_61]],
        },
        0x1A: {  # Engine RPM
            0x01: ["Low Res RPM", "", "", "", ["rpm", PRD.unm_08_71]],
            0x02: ["High Res RPM", "", "", "", ["rpm", PRD.unm_16_31]],
            0x10: ["High Res RPM", "", "", "", ["rpm", PRD.unm_16_31]], # Found on 2001 C5 Z06
            0x20: ["Idle Speed", "Enabled", "Disabled", "", ["rpm", PRD.unm_08_161]],
        },
        0x28: { # Vehicle Speed
            0x01: ["Vehicle Speed", "", "", "", ["km/h", PRD.unm_08_101]],
            0x02: ["Vehicle Speed", "", "", "", ["km/h", PRD.unm_16_5]],
        },
        0x32: { # Brakes
            0x03: ["ABS Active", "Y", "N", "", None],
            0x04: ["ABS System On / Off", "On", "Off", "", None],
            0x09: ["Fluid Life Reset", "R", "~R", "", None],
            0x0A: ["System Faulted", "Y", "N", "", None],
            0x10: ["Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x11: ["Supply Pump Fluid Pressure", "", "", "", ["kPa", PRD.unm_08_171]],
            0x12: ["Fluid Level - Percent", "", "", "", ["%", PRD.unm_08_71]],
            0x13: ["Fluid Level - Volume", "", "", "", ["L", PRD.unm_08_15]],
            0x14: ["Fluid Remaining Life", "", "", "", ["%", PRD.unm_08_61]],
            0x16: ["Fluid Capacity", "", "", "", ["L", PRD.unm_08_15]],
            0x20: ["Parking Brake Sw. Active", "Y", "N", "", None],
            0x21: ["Torque Convertor Clutch - Brake Sw. Active", "Y", "N", "", None],
            0x22: ["Brake Lamp - Brake Sw. Active", "Y", "N", "", None],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", None],
        },
        0x3A: { # Transmission
            0x01: ["Torque Convertor Lock(ed)", "Y", "N", "", None],
            0x02: ["Clutch Enable", "E", "D", "", None],
            0x03: ["Actual Gear Position w/ Shift in Progress", "Y", "N", "", ["", PRD.sed_08_4]],
            0x04: ["Range Selected (PRNDL position)", "", "", "", ["", PRD.sed_08_4]],
            0x05: ["Transfer Case (4WD)", "", "", "", ["", PRD.sed_08_6]],
            0x06: ["Commanded Gear", "", "", "", ["", PRD.sed_08_4]],
            0x07: ["Range Actual (PRNDL sense at transmission)", "", "", "", ["", PRD.sed_08_4]],
            0x08: ["Transmission Kickdown", "Y", "N", "", None],
            0x09: ["Fluid Life Reset", "R", "~R", "", None],
            0x0A: ["Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x0B: ["Fluid Pressure", "", "", "", ["kPa", PRD.unm_08_151]],
            0x0C: ["Fluid Level - Percent", "", "", "", ["%", PRD.unm_08_71]],
            0x0D: ["Fluid Level - Volume", "", "", "", ["L", PRD.unm_08_41]],
            0x0E: ["Fluid Remaining Life", "", "", "", ["%", PRD.unm_08_61]],
            0x10: ["Fluid Capacity", "", "", "", ["L", PRD.unm_08_41]],
            0x14: ["Park/Neutral Sw. Active", "Y", "N", "", None],
            0x1D: ["Fluid Life Reset Sw. Active", "Y", "N", "", None],
        },
        0x48: { # Engine Coolant
            0x10: ["Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x32: ["Low Coolant Level", "Y", "N", "", None],
        },
        0x4A: { # Engine Oil
            0x09: ["Fluid Life Reset", "R", "~R", "", None],
            0x10: ["Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x11: ["Fluid Pressure", "", "", "", ["kPa", PRD.unm_08_141]],
            0x12: ["Fluid Level - Percent", "", "", "", ["%", PRD.unm_08_71]],
            0x13: ["Fluid Level - Volume", "", "", "", ["L", PRD.unm_08_41]],
            0x14: ["Fluid Remaining Life", "", "", "", ["%", PRD.unm_08_61]],
            0x15: ["Oil Viscosity", "", "", "", ["cSt.", PRD.unm_08_41]],
            0x16: ["Fluid Capacity", "", "", "", ["L", PRD.unm_08_41]],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", None],
            0x30: ["Fluid Temperature High", "Y", "N", "", None],
            0x32: ["Low Oil Level", "Y", "N", "", None],
        },
        0x52: { # Engine Systems - Other
            0x04: ["Engine Running", "Y", "N", "", ""],
        },
        0x72: {  # Charging System (Command ID)
            0x01: ["Charging Voltage", "", "", "", ["V", PRD.unm_08_32]],
            0x02: ["Battery Voltage", "", "", "", ["V", PRD.unm_08_32]],
            0x0A: ["Battery Current", "", "", "", ["A", PRD.unm_08_21]],
            0x08: ["Cluster Voltage", "", "", "", ["V", PRD.unm_16_11]], # Found on 2001 C5 Z06
            0x21: ["Charging System Faulted", "Y", "N", "", None],
        },
        0x7A: { # Odometer
            0x01: ["Odometer", "", "", "", ["km", PRD.unm_32_31]],
            0x02: ["Odometer", "", "", "", ["mi", PRD.unm_24_11]], # Found on 2001 C5 Z06
            0x03: ["Trip Reset", "R", "~R", "", None],
            0x04: ["Trip Odometer", "", "", "", ["km", PRD.unm_24_41]],
            0x20: ["Trip Reset Sw. Active", "Y", "N", "", None],
        },
        0x82: {  # Fuel System
            0x0A: ["Unknown Value", "", "", "", None], # Found on 2001 C5 Z06
            0x11: ["Fuel Pressure", "", "", "", ["kPa", PRD.unm_08_131]],
            0x13: ["Fuel Level - Volume", "", "", "", ["L", PRD.unm_16_11]],
            0x16: ["Fuel Capacity", "", "", "", ["L", PRD.unm_16_11]],
            0x32: ["Low Fuel Level", "Y", "N", "", None],
        },
        0x86: { # Ignition
            0x04: ["Ignition Switch Position", "", "", "", ["", PRD.sed_08_5]],
            0x05: ["Key-In-Ignition", "Y", "N", "", None],
        },
        0x88: {  # Tell Tales (Warnings)
            0x01: ["Seatbelt", "On", "Off", "", None],
            0x02: ["Service Engine Soon", "On", "Off", "", None],
            0x03: ["Check Engine (MIL)", "On", "Off", "", None],
            0x04: ["High Beam Indicator", "On", "Off", "", None],
            0x05: ["Left Turn Indicator", "On", "Off", "", None],
            0x06: ["Right Turn Indicator", "On", "Off", "", None],
            0x07: ["Airbag", "On", "Off", "", None],
            0x08: ["Anti-Lock Brake System Failed", "On", "Off", "0", None],
            0x09: ["Traction Control System Failed", "On", "Off", "0", None],
            0x0A: ["Security", "On", "Off", "0", None],
            0x0B: ["Low Fuel", "On", "Off", "0", None],
            0x0C: ["Low Coolant", "On", "Off", "0", None],
            0x0D: ["Low Oil", "On", "Off", "0", None],
            0x0E: ["Low Voltage", "On", "Off", "0", None],
            0x0F: ["Upshift", "On", "Off", "0", None],
            0x10: ["Low Washer Fluid", "On", "Off", "0", None],
            0x11: ["Traction Control Active", "On", "Off", "0", None],
            0x12: ["Alternator Failure", "On", "Off", "0", None],
            0x13: ["Low Brake Fluid", "On", "Off", "0", None],
            0x14: ["Overdrive", "On", "Off", "0", None],
            0x15: ["Traction Control Disabled", "On", "Off", "0", None],
            0x21: ["Convertible Latch Warning", "On", "Off", "0", None],
            0x22: ["Super Lock System Warning", "On", "Off", "0", None],
            0x23: ["Catalyst Over Temperature", "On", "Off", "0", None],
            0x24: ["Vehicle Speed Control", "On", "Off", "0", None]
        },
        0xB2: {  # HVAC (Climate Control)
            0x02: ["Blower Fan Speed", "", "", "", None],
            0x06: ["Multi-Zone Mode", "E", "D", "", None],
            0x07: ["Low Refrigerant", "Y", "N", "", None],
            0x09: ["Fluid Life Reset", "R", "~R", "", None],
            0x0A: ["HVAC Set Temperature", "", "", "8.2", ["°C", PRD.unm_08_73]],
            0x10: ["High Side Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x11: ["High Side Fluid Pressure", "", "", "", ["kPa", PRD.unm_08_159]],
            0x12: ["Fluid Charge - Percent", "", "", "", ["%", PRD.unm_08_61]],
            0x13: ["Fluid Charge - Weight", "", "", "", ["g", PRD.unm_08_155]],
            0x14: ["Fluid Remaining Life", "", "", "", ["%", PRD.unm_08_61]],
            0x16: ["Fluid Capacity - Weight", "", "", "", ["g", PRD.unm_08_155]],
            0x20: ["Low Side Fluid Temperature", "", "", "", ["°C", PRD.unm_08_102]],
            0x21: ["Low Side Fluid Pressure", "", "", "", ["kPa", PRD.unm_08_125]],
            0x22: ["Fan Increment Speed Sw. Active", "Y", "N", "", None],
            0x23: ["Fan Decrement Speed Sw. Active", "Y", "N", "", None],
            0x26: ["Multi-Zone Mode Sw. Active", "Y", "N", "", None],
            0x29: ["Fluid Life Reset Sw. Active", "Y", "N", "", None],
            0x2A: ["Increment Temp Sw. Active", "Y", "N", "", None],
            0x2B: ["Decrement Temp Sw. Active", "Y", "N", "", None],
        },
        0xC4: {  # Door Locks
            0x01: ["Lock", "L", "U", "8.5", None],
            0x02: ["Unlock Enable", "E", "D", "8.5", None],
            0x03: ["Lock Cylinder Secure", "Y", "N", "8.5", None],
            0x04: ["Key-in-Lock Cylinder", "Y", "N", "8.5", None],
            0x05: ["Master Controller Lock", "L", "N", "8.5", None],
            0x06: ["Lock Cylinder State", "L", "U", "8.5", ["", PRD.sed_08_7]],
            0x07: ["Super/Double Lock", "L", "U", "8.5", None],
            0x08: ["Remote Lock w/ Transmitter ID", "L", "U", "8.5", ["", PRD.unm_08_101]],
            0x09: ["Remote Lock", "L", "U", "8.5", None],
            0x10: ["Remote Lock Request", "L", "U", "8.5", None], # Found on 2001 C5 Z06
            0x20: ["Lock Sw Active", "Y", "N", "8.5", None],
            0x21: ["Unlock Sw Active", "Y", "N", "8.5", None],
            0x22: ["Unlock Enable Sw Active", "Y", "N", "8.5", None],
            0x25: ["Master Lock Sw Active", "Y", "N", "8.5", None],
            0x26: ["Master Unlock Sw Active", "Y", "N", "8.5", None],
        },
        0xC6: {  # External Access
            0x01: ["Open", "Y", "N", "8.5", None],
            0x02: ["Close", "Y", "N", "8.5", None],
            0x11: ["Remote Open/Close w/ Transmitter ID", "Open", "Close", "8.5", ["", PRD.unm_08_101]],
            0x12: ["Remote Open/Close", "Open", "Close", "8.5", None],
            0x21: ["Ajar Sw. Active", "Y", "N", "8.5", None],
            0x22: ["Door Handle Sw. Active", "Y", "N", "8.5", None],
            0x23: ["Door Jamb Sw. Active", "Y", "N", "8.5", None],
        },
        0xD2: { # Restraints
            0x01: ["Passive Restraint Enagaged", "Y", "N", "8.6", None],
            0x02: ["Passive Restraint Retracted", "Y", "N", "8.6", None],
            0x03: ["Passive Restraint Attached", "Y", "N", "8.6", None],
            0x04: ["Seatbelt Attached", "Y", "N", "8.6", None],
            0x05: ["Shoulder Adjustment Up Motion", "En", "Dis", "8.6", None],
            0x06: ["Shoulder Adjustment Down Motion", "En", "Dis", "8.6", None],
            0x07: ["Air Bag Deployed", "Y", "N", "8.6", None],
        },
        0xDA: {  # Exterior Lamps
            0x01: ["Headlamp", "On", "Off", "8.8", None],
            0x02: ["Tail Lamp", "On", "Off", "8.8", None],
            0x03: ["Brake Lamp", "On", "Off", "8.8", None],
            0x04: ["Park Lamp", "On", "Off", "8.8", None],
            0x05: ["Turn Lamp", "On", "Off", "8.8", None],
            0x06: ["High Beam Lamp", "On", "Off", "8.8", None],
            0x07: ["Hazard Lamp", "On", "Off", "8.8", None],
            0x08: ["Reverse Lamp", "On", "Off", "8.8", None],
            0x09: ["Fog Lamp", "On", "Off", "8.8", None],
            0x0A: ["Daytime Running Lamp", "On", "Off", "8.8", None],
            0x0B: ["Spot Lamp", "On", "Off", "8.8", None],
            0x0C: ["Cargo Lamp", "On", "Off", "8.8", None],
            0x0D: ["Cornering Lamp", "On", "Off", "8.8", None],
            0x0E: ["Driving Lamp", "On", "Off", "8.8", None],
            0x0F: ["Coach Lamp", "On", "Off", "8.8", None],
            0x10: ["Autolamp Delay", "E", "D", "8.8", ["s", PRD.unm_08_101]],
            0x11: ["Flash-to-Pass", "E", "D", "8.8", None],
            0x12: ["Remote Headlamp On/Off w/Transmitter ID", "On", "Off", "8.8", ["", PRD.unm_08_101]],
            0x13: ["Remote Headlamp", "On", "Off", "8.8", None],
            0x21: ["Headlamp Sw. Active", "Y", "N", "8.8", None],
            0x22: ["Right Turn Sw. Active", "Y", "N", "8.8", None],
            0x24: ["Park Lamp Sw. Active", "Y", "N", "8.8", None],
            0x25: ["Left Turn Sw. Active", "Y", "N", "8.8", None],
            0x26: ["High Beam Sw. Active", "Y", "N", "8.8", None],
            0x27: ["Hazard Sw. Active", "Y", "N", "8.8", None],
            0x28: ["Fog Lamp Sw. Active", "Y", "N", "8.8", None],
            0x29: ["Driving Lamp Sw. Active", "Y", "N", "8.8", None]
        },
        0xDE: {  # Interior Lamps
            0x01: ["Courtesy Lamp", "On", "Off", "8.9", None],
            0x02: ["Dome Lamp", "On", "Off", "8.9", None], 
            0x03: ["Puddle Lamp", "On", "Off", "8.9", None],
            0x04: ["Vanity Mirror Lamp", "On", "Off", "8.9", None],
            0x05: ["Opera Lamp", "On", "Off", "8.9", None],
            0x06: ["Reading Lamp", "On", "Off", "8.9", None],
            0x07: ["Hood Lamp", "On", "Off", "8.9", None],
            0x08: ["Trunk Lamp", "On", "Off", "8.9", None],
            0x09: ["Glove Box Lamp", "On", "Off", "8.9", None],
            0x10: ["Illuminated Entry", "E", "D", "0", None],
            0x11: ["Display Brightness & External Lamps", "On", "Off", "0", ["%", PRD.unm_08_61]],
            0x21: ["Courtesy Lamp Sw. Active", "Y", "N", "8.9", None],
            0x22: ["Dome Lamp Sw. Active", "Y", "N", "8.9", None],
            0x23: ["Puddle Lamp Sw. Active", "Y", "N", "8.9", None],
            0x24: ["Vanity Mirror Sw. Active", "Y", "N", "8.9", None],
            0x25: ["Opera Lamp Sw. Active", "Y", "N", "8.9", None],
            0x26: ["Reading Lamp Sw. Active", "Y", "N", "8.9", None],
            0x27: ["Hood Lamp Sw. Active", "Y", "N", "8.9", None],
            0x28: ["Trunk Lamp Sw. Active", "Y", "N", "8.9", None],
            0x29: ["Glove Box Lamp Sw. Active", "Y", "N", "8.9", None],
        },
        0xEA: { # Display Commands
            0x20: ["Display", "Activate", "Deactivate", "DISP.C5", ["", PRD.dsp_c5_messages]], # Found on 2001 C5 Z06
        },
        0xF2: { # External Environment
            0x10: ["Outside Temperature", "", "", "", ["°C", PRD.unm_08_73]],
            0x11: ["Barometric Pressure", "", "", "", ["kPa", PRD.unm_08_101]],
            0x13: ["Sun Load", "", "", "8.3", ["mW/CM^2", PRD.unm_08_71]],
            0x15: ["Photo Cell Dark", "Yes", "No", "8.3", None]
        },
        0xFA: {  # VIN
            0x01: ["VIN Dig 1", "", "", "", ["", PRD.pkt_32_2]],
            0x02: ["VIN Digit 2-5", "", "", "", ["", PRD.asc_32_1]],
            0x03: ["VIN Digit 6-9", "", "", "", ["", PRD.asc_32_1]],
            0x04: ["VIN Digit 10-13", "", "", "", ["", PRD.asc_32_1]],
            0x05: ["VIN Digit 14-17", "", "", "", ["", PRD.asc_32_1]],
            0x06: ["VIN RSVD", "", "", "", None],
            0x07: ["VIN RSVD", "", "", "", None],
        },
        0xFE: {  # Network Control
            0x02: ["Bus Wake-Up", "Y", "N", "", None],
            0x03: ["Node Alive", "", "", "", None],
            0x04: ["Node Sleep", "Y", "N", "", None],
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
        "DISP.C5": { # Display commands found on 2001 C5 Z06
            0x81: "Change Oil Soon",
            0x82: "Change Oil Now",
            0x84: "Oil Level Low",
            0x89: "Upshift Now",
            0x8E: "Check Gauges",
            0x8F: "Service Vehicle Soon (Ding)",
            0x95: "Service ABS",
            0x96: "ABS Active",
            0x99: "Service Traction System",
            0x9A: "Traction System Active",
            0x9B: "(EBCM: Normal Mode On/Off)",
            0x9E: "(Security Light Solid)",
            0xA5: "Door Ajar",
            0xA6: "Trunk Ajar",
            0xAC: "Service TPMS",
            0xAD: "Service Ride Control",
            0xAE: "Service Vehicle Soon (No Ding)",
            0xB7: "Reduced Engine Power",
            0xB8: "Service Active Handling",
            0xC2: "Active Handling Active",
            0xCB: "High Trans Temp",
            0xD0: "Hatch Ajar",
            0xD3: "Active Handling Warming Up",
            0xD4: "Warm Up Complete",
            0xD5: "Max speed 159 mph",
            0xDE: "Tonnaeu Ajar",
            0xE8: "(EBCM: Comp Mode)",
            0xE9: "Engine Protection, Reduce RPM",
            0xEF: "(Brake Light Icon)",
        }
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
        if (not VPW_frame.is_valid(byteString)):
            return None
        
        try:
            byteArray = bytearray.fromhex(byteString)
        except ValueError:
            print ("Issue processing: ", byteString)
            return None
            
        # OBDX DVI passive RX may omit the trailing VPW CRC; the UI layer appends SAE J1850 CRC-8 when missing so frames match ELM-style captures.
        if len(byteArray) < 4:
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
        if (not ifrBit):
            mode = "?IFR"
            
            # Check for heart beat
        isHeartBeat = False
        if (byteArray[1] == 0xFF or byteArray[1] == 0xFE):
            if byteArray[3] == 0x03 and len(byteArray) in (4, 5):
                isHeartBeat = True

        return {'priority': priority, 'mode': mode, 'mode type': modeType, 'mode operation': modeOp, 'message': byteArray, 'heartbeat': isHeartBeat}
        

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
                    if len(info_list) >= 5 and info_list[4] is not None:  # Check if PRD data exists
                        prd_data = info_list[4]  # 5th field (index 4) - PRD data [unit, function]
                        if isinstance(prd_data, list) and len(prd_data) == 2:
                            unit = prd_data[0]
                            math_function = prd_data[1]
                            
                            if is_extended:
                                # For F Ext messages, PRD data starts at 3rd byte (skip secondary ID and ext address)
                                data_payload = payload[2:] if len(payload) > 2 else []
                            else:
                                # For regular F messages, PRD data starts at 2nd byte (skip secondary ID)
                                data_payload = payload[1:] if len(payload) > 1 else []
                            
                            # Check if we have enough data bytes for the calculation
                            if len(data_payload) > 1:  # Most PRD functions need at least 2 bytes
                                try:
                                    # Handle string references to static methods
                                    if isinstance(math_function, str):
                                        if hasattr(PRD, math_function):
                                            math_function = getattr(PRD, math_function)
                                        else:
                                            print(f"Error: PRD function {math_function} not found")
                                            result = base_description
                                            return (data_value, result)
                                    
                                    if callable(math_function):
                                        calculated_value = math_function(data_payload)
                                        if calculated_value is not None:
                                            if isinstance(calculated_value, (int, float)):
                                                data_value = f"{calculated_value:.2f} {unit}"
                                            else:
                                                data_value = f"{calculated_value} {unit}"
                                except (IndexError, ValueError, ZeroDivisionError) as e:
                                    print(f"Error processing PRD: {e}")
                    
                    # If no PRD data and message type is 'Report Status' or 'Load', show Q-bit value in Data column
                    if not data_value and (msg.get('mode operation') in ['Report Status', 'Load']) and len(info_list) >= 3:
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
        
    def new_message(
        self,
        input_string,
        skip_summary=False,
        transmit_echo=False,
        recv_rel_sec=None,
        live_serial_rx=False,
    ):
        # Send string off to get parsed (add VPW CRC when missing so payload display matches ELM / bus)
        inString = _vpw_hex_line_append_crc_if_missing(input_string.rstrip())
        newMsg = VPW_frame.process(inString)
        
        # If object is NoneType, then it failed to parse. Potentially invalid packet
        if not (newMsg):
            print ("Invalid message recieved in new_message: ", input_string)
            return

        if newMsg["heartbeat"] and self.UIHook.hideHeartbeatsEverywhere.get() and not transmit_echo:
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

        if transmit_echo:
            if description and description != "NA":
                description = "[TX] " + description
            else:
                description = "[TX] (transmitted)"
        
        # Append message to data frame (…, raw hex line, data value, description, relative RX time in s or None)
        self.messageHistory.append(
            [
                len(self.messageHistory),
                newMsg["message"][0],
                taModule,
                saModule,
                newMsg["priority"],
                newMsg["mode"],
                newMsg["mode type"],
                newMsg["message"][3:],
                inString,
                data_value,
                description,
                recv_rel_sec,
            ]
        )

        tempMsg = self.messageHistory[-1]
        tree_tags = ("tx_frame",) if transmit_echo else ()
        self.UIHook.new_message(tempMsg, tags=tree_tags)
        if live_serial_rx and not transmit_echo:
            hx = "".join(inString.split())
            bus_n = len(hx) // 2
            if bus_n > 0:
                self.UIHook.record_serial_rx_sample(bus_n)
        self.UIHook.update_status_bar(len(self.messageHistory))
        
        if skip_summary:
            return
        
        summaryInd = self.find_existing_summary(tempMsg)
        
        # If hide heart beat is enabled, we'll just skip adding it to the summary altogether
        if (newMsg["heartbeat"] and self.UIHook.hideHeartbeats.get()):
            return
        
        if (summaryInd == -1):
            self.messageSummary.append([len(self.messageSummary), 1, tempMsg[0], newMsg["message"][0], taModule, saModule, newMsg["priority"], newMsg["mode"], newMsg["mode type"], newMsg["message"][3:], data_value, description])
            
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
                elif byteCompare == 1:
                    for row in rows:
                        rp, mp = row[9], msg[7]
                        if len(rp) == 0 and len(mp) == 0:
                            return row[0]
                        if len(rp) >= 1 and len(mp) >= 1 and rp[0] == mp[0]:
                            return row[0]
                elif byteCompare == 2:
                    for row in rows:
                        rp, mp = row[9], msg[7]
                        if len(rp) == 0 and len(mp) == 0:
                            return row[0]
                        if len(rp) < 1 or len(mp) < 1:
                            continue
                        if rp[0] != mp[0]:
                            continue
                        if len(rp) == 1:
                            return row[0]
                        if len(mp) >= 2 and rp[1] == mp[1]:
                            return row[0]
            
        return -1
    
    def clear_messages(self):
        return
        
        
'''
Device mode enumeration for type-safe state management
'''
class DeviceMode(Enum):
    DISCONNECTED = "DISCONNECTED"
    MONITOR_MODE = "MONITOR_MODE"
    COMMAND_MODE = "COMMAND_MODE"


'''
ToolManager class manages the OBD device connection state and coordinates
between the device and UI threads. It handles connection/disconnection,
tracks device mode (monitor vs command), and manages message sending.
'''
class ToolManager:
    def __init__(self, message_queue, status_callback=None):
        """
        Initialize the ToolManager
        Args:
            message_queue: Queue object to send messages to UI thread
            status_callback: Optional callback function(status_connected, device_string) for status updates
        """
        self.message_queue = message_queue
        self.status_callback = status_callback
        self.obd = None
        self.reading_thread = None
        self.device_mode = DeviceMode.DISCONNECTED
        self.is_connected = False
        self.device_string = None
        
    def connect(self, file_path, force_elm_protocol=False):
        """
        Connect to OBD device or open file
        Args:
            file_path: Path to serial port or file
            force_elm_protocol: If True and the adapter is OBDX, use ELM AT commands instead of DVI.
        Returns:
            True if successful, False otherwise
        """
        if self.is_connected:
            self.disconnect()
        
        try:
            self.reading_thread = ThreadedTask(
                self, self.message_queue, file_path, force_elm_protocol=force_elm_protocol
            )
            self.reading_thread.start()
            return True
        except Exception as e:
            print(f"Error connecting: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from OBD device and stop reading thread"""
        if self.reading_thread:
            self.reading_thread.stop()
            self.reading_thread.join(3)
            if self.reading_thread.is_alive():
                print("Warning: Reading thread did not stop cleanly")
            self.reading_thread = None
        
        if self.obd:
            self.obd.close()
            self.obd = None
        
        self.is_connected = False
        self.device_mode = DeviceMode.DISCONNECTED
        self.device_string = None
        if self.status_callback:
            self.status_callback(False, "")
    
    def on_device_connected(self, obd_instance, device_string):
        """Called by reading thread when device is connected"""
        self.obd = obd_instance
        self.is_connected = True
        self.device_mode = DeviceMode.MONITOR_MODE  # Device starts in monitor mode
        self.device_string = device_string
        if self.status_callback:
            self.status_callback(True, device_string)
    
    def on_device_disconnected(self):
        """Called when device disconnects"""
        self.is_connected = False
        self.device_mode = DeviceMode.DISCONNECTED
        self.device_string = None
        if self.status_callback:
            self.status_callback(False, "")
    
    def get_device_mode(self):
        """Get current device mode"""
        return self.device_mode
    
    def is_in_monitor_mode(self):
        """Check if device is in monitor mode"""
        return self.device_mode == DeviceMode.MONITOR_MODE
    
    def is_in_command_mode(self):
        """Check if device is in command mode"""
        return self.device_mode == DeviceMode.COMMAND_MODE
    
    def send_message(self, header, payload):
        """
        Send a VPW message via the serial port
        Args:
            header: Header bytes as space-separated hex string (e.g., "8C F1 10")
            payload: Payload bytes as space-separated hex string (e.g., "24 00")
        Returns:
            True if successful, False otherwise
        """
        if not self.obd or not self.is_connected:
            return False
        
        if not self.obd.serial:
            return False  # Can't send to file
        
        # ELM/STN: ATMA must stop for AT commands, then resume. OBDX DVI: send uses 0x10 while RX continues.
        use_elm_atma_cycle = not self.obd.dvi_mode
        if use_elm_atma_cycle and self.device_mode == DeviceMode.MONITOR_MODE:
            self.device_mode = DeviceMode.COMMAND_MODE

        success = self.obd.send_message(header, payload)

        if use_elm_atma_cycle:
            self.device_mode = DeviceMode.MONITOR_MODE

        return success
    
    def get_obd_instance(self):
        """Get the OBD instance (for direct access if needed)"""
        return self.obd


'''
This class is used to run the serial/OBD class in a separate thread
'''
class ThreadedTask(threading.Thread):
    def __init__(self, tool_manager, queue, file_path, force_elm_protocol=False):
        threading.Thread.__init__(self)
        self.tool_manager = tool_manager
        self.file_path = file_path
        self.force_elm_protocol = force_elm_protocol
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
        try:
            self.obd.open(force_elm_protocol=self.force_elm_protocol)
        except Exception as e:
            print(f"Failed to open / configure device: {e}")
            try:
                self.obd.close()
            except Exception:
                pass
            self.obd = None
            return

        # Notify tool manager that device is connected
        if self.tool_manager:
            self.tool_manager.on_device_connected(self.obd, self.obd.dev_string)

        try:
            while not self.stop_var:
                try:
                    # time.sleep(0.1)  # Simulate long running process
                    line, recv_ts = self.obd.read()
                    if self.stop_var:
                        break

                    if not line:
                        if not self.obd.serial:
                            self.end_time = time.perf_counter()
                            self.print_performance_stats()
                            break
                        continue

                    if not line.strip():
                        continue

                    # Count and queue the message
                    self.message_count += 1
                    self.queue.put((line, recv_ts, self.obd.serial))
                except Exception as e:
                    print(f"Exception in file reading thread: {e}")
                    self.end_time = time.perf_counter()
                    self.print_performance_stats()
                    break
        finally:
            if self.obd is not None:
                try:
                    self.obd.close()
                except Exception:
                    pass
                self.obd = None

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
    def __init__(self, root, initial_open=None):
        self.root = root
        self._initial_open = (initial_open or "").strip() or None
        self.queue = queue.Queue()
        # Create ToolManager to handle OBD device state
        self.tool_manager = ToolManager(self.queue, status_callback=self.update_obd_status)
        self._last_send_selection = None
        self._serial_rx_window = deque()
        self.initialize_user_interface()
        self.mm = MessageManager(self)
        self.message_queue_store = MessageQueueStore()
        self._message_queue_toplevel = None
        self.update_status_bar(0)
        # Start the queue processing
        self.update_ui()
        if self._initial_open:
            self.root.after_idle(self._apply_initial_open)

    def _apply_initial_open(self):
        """CLI: pre-fill OBD Device field and run Read/Open (serial port or log file path)."""
        self.serial_port_entry.delete(0, tk.END)
        self.serial_port_entry.insert(0, self._initial_open)
        self.read_file()
 
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
        self.statusBarRxStatsString = tk.StringVar()
        self.statusBarOBDString = tk.StringVar()
        self.messageTreeLock = tk.BooleanVar()
        self.hideHeartbeats = tk.BooleanVar(master=self.root, value=True)
        self.hideHeartbeatsEverywhere = tk.BooleanVar(master=self.root, value=True)
        self.showTransmittedFrames = tk.BooleanVar(master=self.root, value=True)
        self.decodeAsciiPayloadView = tk.BooleanVar(master=self.root, value=False)
        self.forceElmProtocol = tk.BooleanVar(master=self.root, value=False)
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
        self.messageTree = ttk.Treeview(
            self.root,
            columns=("Time", "Hdr", "Prio", "Mode", "Type", "TA", "SA", "Payload", "Data", "Description"),
        )
        self.messageTreeScroll = ttk.Scrollbar(self.root)
        self.messageTreeScroll.configure(command=self.messageTree.yview)
        self.messageTree.configure(yscrollcommand=self.messageTreeScroll.set)
        
        # Set the heading (Attribute Names)
        self.messageTree.heading("#0", text="MID")
        self.messageTree.heading("#1", text="Time (s)")
        self.messageTree.heading("#2", text="Hdr")
        self.messageTree.heading("#3", text="Priority")
        self.messageTree.heading("#4", text="Mode")
        self.messageTree.heading("#5", text="Type")
        self.messageTree.heading("#6", text="TA")
        self.messageTree.heading("#7", text="SA")
        self.messageTree.heading("#8", text="Payload")
        self.messageTree.heading("#9", text="Data")
        self.messageTree.heading("#10", text="Description")
        
 
        # Specify attributes of the columns (We want to stretch it!)
        self.messageTree.column("#0", minwidth=30, width=40, stretch=tk.YES)
        self.messageTree.column("#1", minwidth=52, width=64, stretch=tk.NO)
        self.messageTree.column("#2", minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column("#3", minwidth=40, width=40, stretch=tk.YES)
        self.messageTree.column("#4", minwidth=30, width=30, stretch=tk.YES)
        self.messageTree.column("#5", minwidth=30, width=60, stretch=tk.YES)
        self.messageTree.column("#6", minwidth=30, width=170, stretch=tk.YES)
        self.messageTree.column("#7", minwidth=30, width=80, stretch=tk.YES)
        self.messageTree.column("#8", minwidth=50, width=200, stretch=tk.YES)
        self.messageTree.column("#9", minwidth=50, width=100, stretch=tk.YES)
        self.messageTree.column("#10", minwidth=50, width=300, stretch=tk.YES)
 
        self.messageTree.grid(row=3, column=0, sticky='nsew')
        self.messageTreeScroll.grid(row=3, column=1, sticky='nsw')
        
        # Bind double-click event to message tree
        self.messageTree.bind('<Double-1>', self.on_message_double_click)
        # Last row chosen for "Send Selected Message" — highlight persists until another row is clicked
        for tv in (self.summaryTree, self.messageTree):
            # Strong warm highlight so the send-target row is obvious on grey / default tree rows
            tv.tag_configure("last_send_row", background="#ffb020", foreground="#000000")
        self.messageTree.tag_configure("tx_frame", background="#a5d6a7", foreground="#1b4332")
        self.summaryTree.bind("<<TreeviewSelect>>", self._on_summary_or_message_tree_select)
        self.messageTree.bind("<<TreeviewSelect>>", self._on_summary_or_message_tree_select)
        self.summaryTree.bind("<space>", self._on_trees_space_send_selected)
        self.messageTree.bind("<space>", self._on_trees_space_send_selected)
        for seq in ("<Button-2>", "<Button-3>"):
            self.summaryTree.bind(seq, self._on_summary_tree_context_menu)
            self.messageTree.bind(seq, self._on_message_tree_context_menu)
        
        ''' Configuration Frame '''
        self.config_frame = tk.Frame(self.root, borderwidth = 1)
        self.config_frame.grid(row=1, column = 3, rowspan=1, sticky='nsew')
        self.config_frame.grid_rowconfigure(90, weight=1)
        
        # Define the different GUI widgets
        self.config_label = tk.Label(self.config_frame, text="OBD II Configuration")
        self.config_label.grid(row=0, column=0, columnspan=3, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=1, columnspan = 3, sticky='ew')
        self.serial_label = tk.Label(self.config_frame, text="OBD Dev Path/Log File")
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
 
        self.view_force_elm = tk.Checkbutton(
            self.config_frame,
            text="Force ELM protocol instead of DVI (OBDX adapters)",
            variable=self.forceElmProtocol,
            onvalue=True,
            offvalue=False,
        )
        self.view_force_elm.grid(row=4, column=0, columnspan=3, sticky=tk.W)

        self.close_port_button = tk.Button(self.config_frame, text="Close port", command=self.close_serial_connection)
        self.close_port_button.grid(row=5, column=0, sticky=tk.W)
        self.submit_button = tk.Button(self.config_frame, text="Parse", command=self.insert_data)
        self.submit_button.grid(row=5, column=1, sticky=tk.W)
        self.read_button = tk.Button(self.config_frame, text="Read/Open", command=self.read_file)
        self.read_button.grid(row=5, column=2, sticky=tk.W)
 
 
        # View settings (own rows so they do not overlap Parse / Read/Open)
        self.view_settings_label = tk.Label(self.config_frame, text="View Settings")
        self.view_settings_label.grid(row=6, column=0, columnspan=3, sticky=tk.W)
        config_sep = ttk.Separator(self.config_frame, orient='horizontal')
        config_sep.grid(row=7, columnspan=3, sticky='ew')
        
        self.view_hideHeartbeats = tk.Checkbutton(self.config_frame, text="Hide module heartbeats from summary table", variable=self.hideHeartbeats, onvalue=True, offvalue=False)
        self.view_hideHeartbeats.grid(row=8, column=0, columnspan=3, sticky=tk.W)
        self.view_hideHeartbeatsEverywhere = tk.Checkbutton(self.config_frame, text="Hide module heartbeats from everything", variable=self.hideHeartbeatsEverywhere, onvalue=True, offvalue=False)
        self.view_hideHeartbeatsEverywhere.grid(row=9, column=0, columnspan=3, sticky=tk.W)
        
        self.view_uniqueByte_label = tk.Label(self.config_frame, text="Compare First # Bytes")
        self.view_uniqueByte_label.grid(row=10, column=0, sticky=tk.W)
        self.view_uniqueByte = tk.OptionMenu(self.config_frame, self.messageUniqueByte, "0", "1", "2", "All")
        self.view_uniqueByte.grid(row=10, column=1, sticky=tk.W)

        self.view_decode_ascii_payload = tk.Checkbutton(
            self.config_frame,
            text="Try to decode ASCII in payload column",
            variable=self.decodeAsciiPayloadView,
            onvalue=True,
            offvalue=False,
        )
        self.view_decode_ascii_payload.grid(row=11, column=0, columnspan=3, sticky=tk.W)
        self.decodeAsciiPayloadView.trace_add("write", lambda *_: self._refresh_payload_column_display())

        self.delete_button = tk.Button(self.config_frame, text="Clear Message Logs", command=self.delete_data)
        self.delete_button.grid(row=100, column=0, sticky=tk.W)
        
        self.delete_button = tk.Button(self.config_frame, text="Export Logs", command=self.export_log)
        self.delete_button.grid(row=100, column=1, sticky=tk.W)
 
        
        
        
 
 
 
        ''' Transmit Message Frame '''
        self.transmit_frame = tk.Frame(self.root, borderwidth = 1)
        self.transmit_frame.grid(row=3, column = 3, rowspan=1, sticky='nsew')
        self.transmit_frame.grid_rowconfigure(8, minsize=10)
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
        
        self.view_show_transmitted = tk.Checkbutton(
            self.transmit_frame,
            text="Show transmitted frames in message history",
            variable=self.showTransmittedFrames,
            onvalue=True,
            offvalue=False,
        )
        self.view_show_transmitted.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(2, 4))
        
        self.send_button = tk.Button(self.transmit_frame, text="Send", command=self.on_transmit_send)
        self.send_button.grid(row=5, column=1, sticky='s')
        
        config_sep = ttk.Separator(self.transmit_frame, orient='horizontal')
        config_sep.grid(row=6, columnspan=2, sticky='ew')
        
        self.send_selected_button = tk.Button(self.transmit_frame, text="Send Selected Message", command=self.on_transmit_send_selected)
        self.send_selected_button.grid(row=7, column=0, sticky='s')
        
        self.help_button = tk.Button(self.transmit_frame, text="Help", command=self.show_help)
        self.help_button.grid(row=100, column=1, sticky='s')

        self.message_queues_button = tk.Button(
            self.transmit_frame,
            text="Message queues…",
            command=self.open_message_queue_window,
        )
        self.message_queues_button.grid(row=99, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))
        
        self.exit_button = tk.Button(self.transmit_frame, text="Exit Program", command=self.on_app_close)
        self.exit_button.grid(row=100, column=0, sticky='s')
        
    
        
        ''' Status Bar (message count + optional live stats in separate labels so rates do not shift the count) '''
        self.status_bar_frame = tk.Frame(self.root, bd=1, relief=tk.SUNKEN)
        # Only columns 0–1: the OBD label is gridded from column 2 onward. If we columnspan=5 here, it sits
        # underneath the OBD widget and the throughput text is never visible.
        self.status_bar_frame.grid(row=4, column=0, columnspan=2, sticky="nsew")
        # Fixed-width message column so growing digit counts do not push the throughput label sideways.
        self.status_bar_frame.columnconfigure(0, weight=0, minsize=200)
        self.status_bar_frame.columnconfigure(1, weight=1)
        self.statusBar = tk.Label(
            self.status_bar_frame,
            textvariable=self.statusBarString,
            anchor=tk.W,
            width=26,
            padx=4,
            pady=1,
        )
        self.statusBar.grid(row=0, column=0, sticky="nw")
        self.statusBarRxStats = tk.Label(
            self.status_bar_frame,
            textvariable=self.statusBarRxStatsString,
            anchor=tk.W,
            padx=4,
            pady=1,
        )
        self.statusBarRxStats.grid(row=0, column=1, sticky="nw", padx=(8, 4))
        self.statusBarOBD = tk.Label(self.root, textvariable=self.statusBarOBDString, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.statusBarOBD.grid(row=4, column=2, columnspan=3, sticky="nsew")
        
        
        ''' Reset any variables '''
        self.sid = 0
        self.mid = 0
        self.statusBarString.set("Messages: 0")
        self.statusBarRxStatsString.set("")
        self.statusBarOBDString.set("OBD: Disconnected")
 
 
    def record_serial_rx_sample(self, bus_byte_count):
        """Track live serial VPW frames for rolling bus throughput (VPW bytes, not ASCII wire bytes)."""
        if not self.tool_manager.is_connected:
            return
        obd = self.tool_manager.obd
        if obd is None or not obd.serial:
            return
        now = time.perf_counter()
        self._serial_rx_window.append((now, int(bus_byte_count)))
        self._trim_serial_rx_window(now)

    def _trim_serial_rx_window(self, now=None):
        now = now if now is not None else time.perf_counter()
        cutoff = now - 3.0
        while self._serial_rx_window and self._serial_rx_window[0][0] < cutoff:
            self._serial_rx_window.popleft()

    def _serial_rx_stats_fragment(self):
        """Rolling ~3 s average msg/s and raw VPW bus kbps (kilobits/s); empty when not on serial."""
        obd = getattr(self.tool_manager, "obd", None)
        if not self.tool_manager.is_connected or obd is None or not obd.serial:
            return ""
        now = time.perf_counter()
        self._trim_serial_rx_window(now)
        if not self._serial_rx_window:
            return "0.0 msg/s, 0.00 kbps (bus)"
        oldest = self._serial_rx_window[0][0]
        # Average over actual span in the window (≤3 s), with a small floor to avoid spikes when
        # several frames share the same perf_counter sample.
        span = min(max(now - oldest, 0.05), 3.0)
        n = len(self._serial_rx_window)
        nbytes = sum(b for _, b in self._serial_rx_window)
        msg_per_sec = n / span
        kbps = (nbytes * 8.0) / (span * 1000.0)
        return f"{msg_per_sec:.1f} msg/s, {kbps:.2f} kbps (bus)"

    def update_status_bar(self, messages=None, connected=False):
        if messages is None:
            mm = getattr(self, "mm", None)
            messages = len(mm.messageHistory) if mm else 0
        self.statusBarString.set("Messages: " + str(messages))
        self.statusBarRxStatsString.set(self._serial_rx_stats_fragment())

    def update_message_count(self, messages=0):
        self.messages_receieved = messages
        

    def update_obd_status(self, connected=False, dev_version=""):
        # ToolManager invokes this from the reader thread on connect; Tk is main-thread only.
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, lambda c=connected, d=dev_version: self.update_obd_status(c, d))
            return
        if not connected:
            self._serial_rx_window.clear()
        if connected:
            self.statusBarOBDString.set("OBD: Connected - " + str(dev_version))
        else:
            self.statusBarOBDString.set(str("OBD: Disconnected"))
        self.update_status_bar()
    
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
        
    def _history_has_any_timestamps(self):
        mm = getattr(self, "mm", None)
        if mm is None:
            return False
        for row in mm.messageHistory:
            if len(row) > 11 and row[11] is not None:
                return True
        return False

    def export_log(self):
        """Export logs: path + optional line-leading timestamps (dialog)."""
        if not self.mm.messageHistory:
            messagebox.showinfo("Export", "No messages to export.", parent=self.root)
            return
        has_ts = self._history_has_any_timestamps()
        dlg = tk.Toplevel(self.root)
        dlg.title("Export VPW Logs")
        dlg.transient(self.root)
        dlg.resizable(True, False)

        path_var = tk.StringVar(value="export.txt")
        include_ts = tk.BooleanVar(value=has_ts)

        outer = ttk.Frame(dlg, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(outer, text="File:").grid(row=0, column=0, sticky=tk.W)
        ent = ttk.Entry(outer, textvariable=path_var, width=52)
        ent.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 6))

        def browse():
            p = filedialog.asksaveasfilename(
                parent=dlg,
                title="Export VPW Logs",
                defaultextension=".txt",
                filetypes=[
                    ("Text files", "*.txt"),
                    ("Log files", "*.log"),
                    ("All files", "*.*"),
                ],
                initialfile=path_var.get().strip() or "export.txt",
            )
            if p:
                path_var.set(p)

        ttk.Button(outer, text="Browse…", command=browse).grid(row=1, column=2, padx=(6, 0), pady=(2, 6))

        chk = ttk.Checkbutton(
            outer,
            text="Include relative timestamps (0.000 s) at the start of each line",
            variable=include_ts,
        )
        chk.grid(row=2, column=0, columnspan=3, sticky=tk.W)
        if not has_ts:
            include_ts.set(False)
            chk.state(["disabled"])

        err_lbl = ttk.Label(outer, text="", foreground="#a00")
        err_lbl.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(4, 0))

        btn_row = ttk.Frame(outer)
        btn_row.grid(row=4, column=0, columnspan=3, pady=(10, 0))

        def do_export():
            file_path = path_var.get().strip()
            if not file_path:
                err_lbl.config(text="Choose a file path.")
                return
            want_ts = bool(include_ts.get()) and has_ts
            try:
                with open(file_path, "w", encoding="utf-8", newline="") as fexport:
                    for row in self.mm.messageHistory:
                        raw = row[8]
                        ts = row[11] if len(row) > 11 else None
                        if want_ts and ts is not None:
                            fexport.write(_format_vpw_export_timestamp(ts) + " " + raw + "\r\n")
                        else:
                            fexport.write(raw + "\r\n")
                print(f"Logs exported successfully to: {file_path}")
                dlg.destroy()
            except Exception as e:
                err_lbl.config(text=str(e))

        ttk.Button(btn_row, text="Export", command=do_export).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT)

        outer.columnconfigure(0, weight=1)
        dlg.grab_set()
        ent.focus_set()

    def _current_recv_timestamp_for_transmit_echo(self):
        obd = getattr(self.tool_manager, "obd", None)
        if obd is None or not obd.serial:
            return None
        t0 = getattr(obd, "_vpw_capture_t0", None)
        if t0 is None:
            return None
        return time.perf_counter() - t0
        

    def new_message(self, newMsg, tags=()):
        # Print the message to the message history tree
        self.messageTree.insert(
            "",
            "end",
            iid=newMsg[0],
            text=str(newMsg[0]),
            values=self._message_history_tree_values_tuple(newMsg),
            tags=tags,
        )

        # If the scroll lock is enabled, then scroll down
        if (self.messageTreeLock.get()):
            self.messageTree.yview_moveto(1)
            
        self.update_status_bar()
        
        
        
    def new_message_summary(self, newMsg):        
        # Print the message to the message history tree
        self.summaryTree.insert(
            "",
            "end",
            iid=newMsg[0],
            text=str(newMsg[0]),
            values=self._summary_tree_values_tuple(newMsg),
        )
        #self.sid = self.sid + 1
        
        
    def update_message_summary(self, index, newMsg):
        try:
            self.summaryTree.item(
                index,
                text=str(index),
                values=self._summary_tree_values_tuple(newMsg),
            )
        except ValueError:
            print ("Issue updating index, ", newMsg)
            for child in self.summaryTree.get_children():
                print(self.summaryTree.item(child)["values"])

    def _message_history_tree_values_tuple(self, hist_row):
        try_ascii = self.decodeAsciiPayloadView.get()
        pl = _vpw_payload_column_text(hist_row[7], try_ascii)
        ts = hist_row[11] if len(hist_row) > 11 else None
        ts_txt = _format_vpw_export_timestamp(ts) if ts is not None else ""
        return (
            ts_txt,
            "{:02X}".format(hist_row[1]),
            hist_row[4],
            hist_row[5],
            hist_row[6],
            hist_row[2],
            hist_row[3],
            pl,
            hist_row[9],
            hist_row[10],
        )

    def _summary_tree_values_tuple(self, sum_row):
        try_ascii = self.decodeAsciiPayloadView.get()
        pl = _vpw_payload_column_text(sum_row[9], try_ascii)
        return (
            sum_row[2],
            sum_row[1],
            "{:02X}".format(sum_row[3]),
            sum_row[6],
            sum_row[7],
            sum_row[8],
            sum_row[4],
            sum_row[5],
            pl,
            sum_row[10],
            sum_row[11],
        )

    def _refresh_payload_column_display(self):
        mm = getattr(self, "mm", None)
        if mm is None:
            return
        try:
            for iid in self.messageTree.get_children():
                idx = int(iid)
                row = mm.messageHistory[idx]
                self.messageTree.item(iid, values=self._message_history_tree_values_tuple(row))
        except (ValueError, IndexError, tk.TclError):
            pass
        try:
            for iid in self.summaryTree.get_children():
                idx = int(iid)
                row = mm.messageSummary[idx]
                self.summaryTree.item(iid, values=self._summary_tree_values_tuple(row))
        except (ValueError, IndexError, tk.TclError):
            pass

    def delete_data(self):
        #row_id = int(self.summaryTree.focus())
        #self.summaryTreeview.delete(row_id)
        for i in self.summaryTree.get_children():
            self.summaryTree.delete(i)
            
        for i in self.messageTree.get_children():
            self.messageTree.delete(i)
        
        self._last_send_selection = None
            
        self.mm = MessageManager(self)
        self._serial_rx_window.clear()
        obd = getattr(self.tool_manager, "obd", None)
        if self.tool_manager.is_connected and obd is not None:
            obd.reset_vpw_capture_epoch()

        self.mid = 0
        self.sid = 0
        self.update_status_bar(0)

    def read_file(self):
        file_path = self.serial_port_entry.get()
        # Use ToolManager to handle connection
        self.tool_manager.connect(file_path, force_elm_protocol=self.forceElmProtocol.get())

    def close_serial_connection(self):
        """Stop the reading thread and close the serial port (or file handle) cleanly."""
        self.tool_manager.disconnect()

    def _clear_last_send_row_highlight(self):
        if not self._last_send_selection:
            return
        tree, iid = self._last_send_selection
        try:
            tree.item(iid, tags=())
        except tk.TclError:
            pass
        self._last_send_selection = None

    def _set_last_send_row_highlight(self, tree, iid):
        """One row across both trees keeps tag last_send_row until another row is chosen."""
        if self._last_send_selection and self._last_send_selection[0] == tree and self._last_send_selection[1] == iid:
            return
        self._clear_last_send_row_highlight()
        try:
            tree.item(iid, tags=("last_send_row",))
            self._last_send_selection = (tree, iid)
        except tk.TclError:
            self._last_send_selection = None

    def _on_summary_or_message_tree_select(self, event):
        w = event.widget
        if w not in (self.summaryTree, self.messageTree):
            return
        sel = w.selection()
        if not sel:
            return
        self._set_last_send_row_highlight(w, sel[0])

    def _on_trees_space_send_selected(self, event):
        if event.widget not in (self.summaryTree, self.messageTree):
            return
        self.on_transmit_send_selected()
        return "break"

    def _maybe_record_transmit_echo(self, hdr, pl):
        if not self.showTransmittedFrames.get():
            return
        line = f"{hdr} {pl}".strip()
        self.mm.new_message(
            line,
            skip_summary=True,
            transmit_echo=True,
            recv_rel_sec=self._current_recv_timestamp_for_transmit_echo(),
        )

    def on_transmit_send(self):
        """Send Header + Payload using DVI (OBDX) or ELM/STN path."""
        if not self.tool_manager.is_connected:
            messagebox.showwarning("Not connected", "Open a serial device with Read/Open first.")
            return
        if not self.tool_manager.obd or not self.tool_manager.obd.serial:
            messagebox.showinfo("Transmit", "Transmit is only available on a live serial connection, not from a log file.")
            return
        hdr = self.header_entry.get().strip()
        pl = self.payload_entry.get().strip()
        if not hdr or not pl:
            messagebox.showwarning("Transmit", "Enter both Header and Payload (hex bytes).")
            return
        ok = self.tool_manager.send_message(hdr, pl)
        if ok:
            self._maybe_record_transmit_echo(hdr, pl)
            cur = self.statusBarOBDString.get()
            if cur.startswith("OBD: Connected"):
                base = cur.split(" — ")[0]
                self.statusBarOBDString.set(base + " — Last transmit: OK")
        else:
            messagebox.showerror(
                "Transmit failed",
                "The adapter did not acknowledge the send. Check hex fields and connection.",
            )

    def on_transmit_send_selected(self):
        """Send the last single-clicked row from Summary or Message history (see highlight)."""
        if not self.tool_manager.is_connected:
            messagebox.showwarning("Not connected", "Open a serial device with Read/Open first.")
            return
        if not self.tool_manager.obd or not self.tool_manager.obd.serial:
            messagebox.showinfo("Transmit", "Transmit is only available on a live serial connection, not from a log file.")
            return
        if not self._last_send_selection:
            messagebox.showwarning(
                "No row chosen",
                "Click a row in Summary or Message history to choose what to send (it will highlight).",
            )
            return
        tree, iid = self._last_send_selection
        try:
            tree.item(iid, "values")
        except tk.TclError:
            self._last_send_selection = None
            messagebox.showwarning("Send target", "That row no longer exists. Click another message.")
            return
        pair = self._header_payload_from_tree(tree, iid)
        if not pair:
            messagebox.showerror("Send target", "Could not build a frame from the selected row.")
            return
        hdr, pl = pair
        self.header_entry.delete(0, tk.END)
        self.header_entry.insert(0, hdr)
        self.payload_entry.delete(0, tk.END)
        self.payload_entry.insert(0, pl)
        ok = self.tool_manager.send_message(hdr, pl)
        if ok:
            self._maybe_record_transmit_echo(hdr, pl)
            cur = self.statusBarOBDString.get()
            if cur.startswith("OBD: Connected"):
                base = cur.split(" — ")[0]
                self.statusBarOBDString.set(base + " — Last transmit: OK")
        else:
            messagebox.showerror(
                "Transmit failed",
                "The adapter did not acknowledge the send. Check the highlighted row and connection.",
            )

    def update_ui(self):
        # Process any messages in the queue
        try:
            while True:
                item = self.queue.get_nowait()
                if isinstance(item, tuple) and len(item) == 3:
                    line, recv_ts, live_serial = item
                elif isinstance(item, tuple) and len(item) == 2:
                    line, recv_ts = item
                    live_serial = False
                else:
                    line, recv_ts, live_serial = item, None, False
                self.mm.new_message(line, recv_rel_sec=recv_ts, live_serial_rx=live_serial)
        except queue.Empty:
            pass

        # Always refresh from the UI thread so stats reappear after reconnect (Tk StringVars are not
        # safe to update from the reader thread; see update_obd_status).
        self.update_status_bar()

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
            self.populate_transmit_frame(self.summaryTree, item)
    
    def on_message_double_click(self, event):
        """Handle double-click on message tree to populate transmit frame"""
        item = self.messageTree.selection()[0] if self.messageTree.selection() else None
        if item:
            self.populate_transmit_frame(self.messageTree, item)

    def _header_payload_from_tree(self, tree, iid):
        """Build transmit header + payload hex from tree row (payload always from stored bytes)."""
        is_summary = tree is self.summaryTree
        try:
            vals = tree.item(iid, "values")
            idx = int(iid)
        except (tk.TclError, ValueError, TypeError):
            return None
        try:
            if is_summary:
                if idx < 0 or idx >= len(self.mm.messageSummary) or len(vals) < 10:
                    return None
                raw_pl = self.mm.messageSummary[idx][9]
                hdr, ta, sa = vals[2], vals[6], vals[7]
            else:
                if idx < 0 or idx >= len(self.mm.messageHistory) or len(vals) < 7:
                    return None
                raw_pl = self.mm.messageHistory[idx][7]
                hdr, ta, sa = vals[1], vals[5], vals[6]
        except (IndexError, TypeError):
            return None
        try:
            ta_hex = self.extract_hex_from_column(ta)
            sa_hex = self.extract_hex_from_column(sa)
            if ta_hex and sa_hex:
                header = f"{hdr} {ta_hex} {sa_hex}"
            else:
                header = str(hdr)
            pl = _vpw_payload_hex_for_transmit(raw_pl)
            return (header.strip(), pl.strip())
        except (TypeError, ValueError):
            return None

    def populate_transmit_frame(self, tree, item):
        """Populate transmit frame fields with data from selected row"""
        try:
            pair = self._header_payload_from_tree(tree, item)
            if not pair:
                print("Error: Not enough columns or bad data in tree row")
                return
            header, payload = pair
            self.header_entry.delete(0, tk.END)
            self.payload_entry.delete(0, tk.END)
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
        
        # Help content (defined at top of file)
        text_widget.insert(tk.END, HELP_TEXT)
        text_widget.config(state=tk.DISABLED)  # Make read-only
        
        # Add close button
        close_button = tk.Button(help_window, text="Close", command=help_window.destroy)
        close_button.pack(pady=10)

    def open_message_queue_window(self):
        open_or_raise_message_queue_window(self)

    def _on_summary_tree_context_menu(self, event):
        self._tree_context_menu(event, self.summaryTree, is_summary=True)

    def _on_message_tree_context_menu(self, event):
        self._tree_context_menu(event, self.messageTree, is_summary=False)

    def _tree_context_menu(self, event, tree, is_summary):
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        self._set_last_send_row_highlight(tree, row)
        try:
            vals = tree.item(row, "values")
        except tk.TclError:
            return
        pair = self._header_payload_from_tree(tree, row)
        if not pair:
            return
        hdr, pl = pair
        desc = description_from_tree_values(vals, is_summary)
        menu = tk.Menu(self.root, tearoff=0)
        sub = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Add to queue", menu=sub)
        sub.add_command(
            label="New queue…",
            command=lambda h=hdr, p=pl, d=desc: self._context_add_message_new_queue(h, p, d),
        )
        if self.message_queue_store.groups:
            sub.add_separator()
            for i, g in enumerate(self.message_queue_store.groups):
                label = g["name"]
                if len(label) > 52:
                    label = label[:49] + "…"
                sub.add_command(
                    label=label,
                    command=lambda idx=i, h=hdr, p=pl, d=desc: self._context_append_message_to_queue(idx, h, p, d),
                )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _context_add_message_new_queue(self, hdr, pl, desc):
        name = simpledialog.askstring("New queue", "Queue name:", parent=self.root)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        idx = self.message_queue_store.add_group(name)
        self.message_queue_store.append_message(idx, hdr, pl, desc)
        self._refresh_message_queue_window_if_open()

    def _context_append_message_to_queue(self, group_index, hdr, pl, desc):
        self.message_queue_store.append_message(group_index, hdr, pl, desc)
        self._refresh_message_queue_window_if_open()

    def _refresh_message_queue_window_if_open(self):
        mq = getattr(self, "_message_queue_toplevel", None)
        if mq is None:
            return
        try:
            if mq.win.winfo_exists():
                mq.refresh_preserve_selection()
        except tk.TclError:
            pass

    def on_app_close(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            # Disconnect via ToolManager
            self.tool_manager.disconnect()
            destroy_message_queue_window_if_any(self)
            self.root.destroy()




if __name__ == "__main__":
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    app = Application(tk.Tk(), initial_open=initial)
    app.root.wm_protocol("WM_DELETE_WINDOW", app.on_app_close)
    app.root.mainloop()
