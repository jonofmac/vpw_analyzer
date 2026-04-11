These are example VPW logs that I recorded on my 2001 C5 Z06 and some from my 2006 C6 Z06

Logs in this folder:
- abs_active_handling_msg.txt
- key_on.txt
- tcs_button_press.txt
- open_trunk_with_fob_c6.txt

abs_active_handling_msg.txt (C5)
    Driving in snow and intentionally activating active handling and ABS
    messages.

key_on.txt (C5)
    Turning the key from the off position to the on position (not cranking).
    Modules wake up and send a lot of traffic.

tcs_button_press.txt (C5)
    With the car on, but engine not running, pressing the TCS disable button
    once. In the C5, this fully disables active handling as well as traction
    control. ABS remains active. The BCM detects the button press and sends
    a message to the ABS module. ABS module sends a message to ack the
    request and then displays the current status.

open_trunk_with_fob_c6.txt (C6)
    With the car off and locked and all doors closed, I press the "open hatch"
    button on my wireless keyfob. Then I press the unlock button 3x times,
    which turns on the running lights.