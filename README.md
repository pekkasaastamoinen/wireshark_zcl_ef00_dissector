# wireshark_zcl_ef00_dissector
A Lua dissector for Zigbee 0xef00 ZCL clusters.

# Installation
You can check where Wireshark stores files in Help -> About Wireshark -> Folders.

"Personal Lua Plugins" is a good choice.

Copy zcl_ef00.lua to the chosen directory.

# Limitations
Currently tested only with a device sending just Value and Enum packets, using Wireshark Version 3.6.2 (Git v3.6.2 packaged as 3.6.2-2).
