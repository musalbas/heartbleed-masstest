#!/bin/sh

cd /root/heartbleed-masstest


OUTPUT_FILE="data/portscan.txt"
INPUT_FILE="data/is-net.txt"

echo "" > $OUTPUT_FILE

for i in $(cat $INPUT_FILE); do
        echo "Scanning $i"
        masscan -p443 --rate 10000 $i >> $OUTPUT_FILE
done

python import_from_massscan.py
git commit $OUTPUT_FILE -m "Ran portscan"
