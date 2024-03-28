-- Zigbee 0xef00 cluster Wireshark dissector
--
-- Copyright (C) 2024 psaastam@iki.fi
-- 
-- License:
-- GNU General Public License v2.0 only
-- GPL-2.0
--
-- Info mostly from
-- https://github.com/zigbeefordomoticz/wiki/blob/master/en-eng/Technical/Tuya-0xEF00.md
--
zcl_ef00_protocol = Proto("zcl_ef00", "ZCL EF00 cluster")

-- +-----------+----------+------------------+--------------+-------------+------------+-------+-------------+
-- | 0 command | 1 status | 2 transaction Id | 3 Data Point | 4 Data Type | 5 Function | 6 Len | 7 Data      |
-- +-----------+----------+------------------+--------------+-------------+------------+-------+-------------+
-- | uint8     | uint8    | uint8            | uint8        | uint8       | uint8      | uint8 | len * uint8 |
-- +-----------+----------+------------------+--------------+-------------+------------+-------+-------------+

-- Enumerate the protocol fields
Cmd = ProtoField.uint8("ef00.cmd", "Command", base.DEC)
Status = ProtoField.uint8("ef00.status", "Status", base.DEC)
TransactionID = ProtoField.uint8("ef00.transid", "TransactionID", base.DEC)
DataPoint = ProtoField.uint8("ef00.dp", "DataPoint", base.DEC)
DataType = ProtoField.uint8("ef00.dt", "DataType", base.DEC)
Function = ProtoField.uint8("ef00.func", "Function", base.DEC)
Len = ProtoField.uint8("ef00.len", "Data length", base.DEC)
Data = ProtoField.bytes("ef00.data", "Data bytes", base.NONE)

zcl_ef00_protocol.fields = {
    Cmd, Status, TransactionID, DataPoint, DataType, Function, Len, Data
}

function zcl_ef00_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- skip column naming to keep parent name
    -- pinfo.cols.protocol = tuya_ef00_protocol.name

    local subtree = tree:add(zcl_ef00_protocol, buffer(),
                             "Zigbee, 0xEF00 Cluster")
    local cmd, status, transaction, data_point, data_type, func, data_len, data
    local info = "ZCL 0xEF00"

    cmd = buffer(0, 1):int()
    subtree:add(Cmd, buffer(0, 1)):append_text(" " .. get_command_name(cmd))
    -- skip commands other than 1 and 2, just dump rest of buffer as Data
    if cmd > 0x02 then
        subtree:add(Data, buffer(1, length - 1))
        goto done
    end
    if length > 1 then
        status = buffer(1, 1):int()
        subtree:add(Status, buffer(1, 1))
    end
    if length > 2 then
        transaction = buffer(2, 1):int()
        subtree:add(TransactionID, buffer(2, 1))
    end
    if length > 3 then
        data_point = buffer(3, 1):int()
        info = info .. (string.format(", DP: %i", data_point))
        subtree:add(DataPoint, buffer(3, 1)):append_text(string.format(
                                                             " (0x%02x)",
                                                             data_point))
    end
    if length > 4 then
        data_type = buffer(4, 1):int()
        info = info ..
                   (string.format(", dtype: %s", get_datatype_name(data_type)))
        subtree:add(DataType, buffer(4, 1)):append_text(" " ..
                                                            get_datatype_name(
                                                                data_type))
    end
    if length > 5 then
        func = buffer(5, 1):int()
        subtree:add(Function, buffer(5, 1))
    end
    if length > 6 then
        data_len = buffer(6, 1):int()
        subtree:add(Len, buffer(6, 1))
    end
    if length > 7 and length > (data_len + 6) then
        local buf = buffer(7, data_len)
        data = buf:int()
        if data_type == 1 then -- bool
            if val > 0 then
                info = info .. (string.format(", data: True", buf:bool()))

                subtree:add(Data, buf):append_text(" True/On/1")
            else
                info = info .. (string.format(", data: False", buf:bool()))
                subtree:add(Data, buf):append_text(" False/Off/0")
            end
        elseif data_type == 0x02 then -- value
            info = info .. (string.format(", data: %i", data))

            if data_len == 4 then

                subtree:add(Data, buf):append_text(string.format(
                                                       " (dec:%d, hex:0x%02x)",
                                                       data, data))
            elseif data_len < 4 then
                subtree:add(Data, buf)
            else
                subtree:add(Data, buf):append_text(" Unsupported data length")
            end
        elseif data_type == 0x03 then -- string
            info = info .. (string.format(", data: %s", buf))
            subtree:add(Data, buf):append_text(string.format(" \"%s\"", buf))
        elseif data_type == 0x04 then -- enum
            info = info .. (string.format(", data: %d", data))
            subtree:add(Data, buf):append_text(" (enum)")
        elseif data_type == 0x05 then -- fault
            info = info .. (string.format(", data: %d", data))
            subtree:add(Data, buf):append_text(" (fault)")
        else
            subtree:add(Data, buf)
        end
    end

    ::done::
    pinfo.cols.info:append(info)

end

-- helper functions for getting string representations of some of the enummy fields
--

function get_command_name(cmd)
    -- 0x01 - Query and report product information, 0x02 - Device Status Query / Report
    local cmd_name = string.format(" Unknown", cmd)

    if cmd == 0x01 then
        cmd_name = "Query and report product info"
    elseif cmd == 0x02 then
        cmd_name = "Device Status Query / Report"
    elseif cmd == 0x03 then
        cmd_name = "Zigbee Device Reset"
    elseif cmd == 0x04 then
        cmd_name = "Order Issuance"
    elseif cmd == 0x05 then
        cmd_name = "Status Report"
    elseif cmd == 0x06 then
        cmd_name = "Status Search"
    elseif cmd == 0x07 then
        cmd_name = "Reserved"
    elseif cmd == 0x08 then
        cmd_name = "Zigbee Device Functional Test"
    elseif cmd == 0x09 then
        cmd_name = "Query key information"
    elseif cmd == 0x0A then
        cmd_name = "Scene wakeup"
    elseif cmd > 0x0A and cmd < 0x24 then
        cmd_name = "Reserved"
    elseif cmd == 0x24 then
        cmd_name = "Time synchonization"
    end
    return cmd_name
end

function get_datatype_name(dt)
    local dt_name = "Unknown"

    if dt == 0 then
        dt_name = "RAW"
    elseif dt == 1 then
        dt_name = "BOOL"
    elseif dt == 2 then
        dt_name = "VALUE"
    elseif dt == 3 then
        dt_name = "STRING"
    elseif dt == 4 then
        dt_name = "ENUM"
    elseif dt == 5 then
        dt_name = "FAULT"
    end
    return dt_name
end

-- register the dissector for zcl clusters with id 0xef00
local wpan_dist = DissectorTable.get("zbee.zcl.cluster")
if wpan_dist then wpan_dist:add(0xef00, zcl_ef00_protocol) end

