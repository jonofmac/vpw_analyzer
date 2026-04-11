# VPW Analyzer

A visual J1850 VPW analyzer written in Python for GM VPW used on 1997–2013 (Gen 3 and 4) vehicles.

## Requirements

- **Python 3**
- **Tkinter** — required for the whole UI; it ships with the official Windows/macOS Python installers. On Debian/Ubuntu-style Linux, install the OS package if `import tkinter` fails, e.g. `sudo apt install python3-tk` (it is not the same as `pip install tk`).
- **Pandas** and **pyserial** (`import serial`) — typically from pip:

```
pip3 install pandas pyserial
```

## Running

```
python3 vpw_analyzer.py
```

You can pass a log file path on the command line; the path is filled in and **Read/Open** runs automatically:

```
python3 vpw_analyzer.py /path/to/log.txt
```

## Supported adapters

- **ELM327-style devices** — Passive listen uses basic AT commands (`AT SP 2`, `AT H1`, `AT MA`). **Transmit** stops monitoring briefly to issue `AT SH` and send the payload, then resumes `AT MA`. This is a limitation of the ELM327 protocol.
- **OBDX Pro VT** (and other tools that identify as OBDX) — After probe, the app switches to the **DVI** binary API for VPW passive monitoring and **transmit**. Sends use DVI “send to network” framing while monitoring continues, so the bus is not dropped between frames the way it is on ELM during each send.

If a previous session left the adapter in DVI mode, the app attempts to switch back to ELM text mode (or reboot the interface) before normal AT setup.

## How to use

Enter the serial port in **OBD Device Serial Port** and press **Read/Open** to connect and start decoding.

- **Windows:** typically `COM1`, `COM3`, etc. (check Device Manager).
- **Linux and MacOS:** full device path, e.g. `/dev/ttyUSB0`, `/dev/ttyACM0`.

For **offline** analysis, put the path to a VPW log (one frame per line) in the same field and press **Read/Open**.

The **top** table lists **unique** messages (grouping controlled by **Compare First # Bytes**). The **bottom** table is **Message history** in receive order.

**Clear Message Logs** clears both tables. On an active serial connection it also **restarts the relative time base** used for timestamps (see below).

**Export Logs** writes the raw hex lines; the export dialog can optionally prepend relative timestamps when the history has them.

## Frame decoding (known vs unknown)

Every **valid** VPW line is parsed into bus structure: **priority**, **mode**, **mode type**, **TA**, **SA**, and the **payload** bytes (plus the full original hex line used for export and transmit). Malformed lines are skipped.

On top of that, the app ships with **GM-oriented tables** (functional command addresses, secondary IDs / message names, physical module names, and PRD-style scaling for some payloads). When a frame matches those entries, the **Description** and **Data** columns show **human-readable text** and decoded values where implemented.

For traffic **outside** those tables, you still get correct structural columns and **full hex in Header / Payload**, but the “English” side stays **minimal or generic**:

- **Physical addressing** (non-functional): **TA** / **SA** show a module name when the address is in the catalog, otherwise a plain **`$hh`** address. **Description** stays **`NA`** and **Data** is left empty — the bytes are only in the payload column.
- **Functional** messages: if the functional target or secondary ID is not cataloged, **Description** falls back to the **VPW operation** in parentheses (for example `(Load)` or `(Report Status)`), without a specific signal name, and **Data** is usually empty unless a decoder matched.

So “unknown” does not mean the frame is hidden: it means **no curated label or numeric decode**, while the **raw frame content remains visible** as hex in the tables and in exported logs.

## Timestamps

- **Live serial:** Each frame gets a **relative receive time** in seconds, measured from when passive VPW capture started (after `AT MA` on ELM, or after DVI “network on” on OBDX). Values appear in Message history under **Time (s)** (three decimal places in exports and that column).
- **Log files:** Each line may be **only** hex, or **`seconds` + space + hex**, where `seconds` uses **exactly three** fractional digits (e.g. `12.345 8C F1 10 …`). **Read/Open** accepts both forms; prefixed lines restore per-line times into the history.
- **Export:** **Export Logs** offers **Include relative timestamps** when any row has a time; lines without a stored time are exported as hex only.

## Transmitting frames

Use **Header** and **Payload** (space-separated hex), then **Send**. **Send Selected Message** uses the highlighted row in Summary or Message history (single click to select; double-click still fills transmit fields only).

Successful sends can be mirrored into Message history as green-tagged rows when **Show transmitted frames in message history** is enabled.

## Message queue groups

Named **queues** hold ordered VPW frames as **header**, **payload**, and optional **description**.

- Open **Message queues…** from the transmit area to create, rename, duplicate, or delete queues; reorder messages with **Up** / **Down**; remove rows; **Export…** / **Import…** JSON.
- **Right-click** a row in Summary or Message history → **Add to queue** (new queue or append to an existing one).
- **Send entire queue** walks the list in order. **Sending many frames in quick succession without losing passive monitoring between sends is intended for OBDX Pro in DVI mode.** On ELM, each send still cycles out of `AT MA` and back, so rapid queue runs are slower and may not match “back-to-back on the wire” behavior.
- **Load into transmit** copies the selected queue row into the Header / Payload fields.

Import accepts either a top-level JSON **array** of queue objects or an object with a **`queues`** array; exports use `"format": "vpw_analyzer_message_queues"` for clarity.


## Known issues / limitations

- Queue **Send entire queue** is most reliable for tight timing on **OBDX Pro VT** DVI compatible devices; ELM adapters remain supported for single-frame transmit and passive listen.
