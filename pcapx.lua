--[[-
pcapx - extensions to pcap

]]

require"pcap"
require"net"

local function NOP()
end

--[[-
- pcap.recode(incap, outcap, progress, debug)

- incap, name of input pcap
- outcap, name of output pcap, default to "recoded-"..incap
- progress, pass print-like function to receive progress messages,
  defaults to no progress
- debug, as above, but for debug output

Re-encode file.pcap as recoded-file.pcap, using print()
to report progress:

  pcap.recode("file.pcap", nil, print)
]]
function pcap.recode(incap, outcap, progress, debug)
    progress = progress or NOP
    debug = debug or NOP

    if not outcap then
        outcap = "recoded-"..incap
    end
    os.remove(outcap)

    local cap = assert(pcap.open_offline(incap))
    local dmp = assert(cap:dump_open(outcap))
    local n = assert(net.init())
    local i = 0
    for pkt, time, len in cap.next, cap do
        i = i + 1
        progress("packet", i, "wirelen", len, "timestamp", time, os.date("!%c", time))
        assert(n:clear())
        assert(n:decode_eth(pkt))
        assert(dmp:dump(n:block(), time, len))
        debug(n:dump())
    end
    dmp:close()
    cap:close()
    n:destroy()
    return outcap
end

