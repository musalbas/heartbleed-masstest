#!/bin/sh

OUTPUT_FILE="data/portscan.txt"
INPUT_FILE="data/is-net.txt"

echo "" > $OUTPUT_FILE

for i in $(cat $INPUT_FILE); do
        echo "Scanning $i"
        masscan -p443 --rate 100000 $i >> $OUTPUT_FILE
done

