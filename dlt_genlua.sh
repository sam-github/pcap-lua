#!/bin/bash


for dlt in $@; do
    DLT="$(awk '{print toupper($0)}' <<< "$dlt")"
    echo '#ifdef DLT_'"$DLT"
    echo '    pcap_dlt_set(L, "'"$DLT"'", DLT_'"$DLT"');'
    echo '#endif'
done
