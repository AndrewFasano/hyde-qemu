#!/bin/bash
set -eux

OUTPUT_FILE=/tmp/log_$(date +%s).txt

#USAGE: ./benchmark.sh "qemu-system qemu-args -more -args" "guest command; more guest cmds"


expect -c "
spawn $1
send \"\r\"
expect \"ubuntu@ubuntu:~*\"
send \"$2\r\"
set timeout 1200
expect \"ubuntu@ubuntu:~*\"

set output \$expect_out(buffer)
set file [open \"${OUTPUT_FILE}\" \"w\"]
puts \$file \$output
close \$file

set timeout 10
send \"\001x\"
expect eof
"

sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' $OUTPUT_FILE > $OUTPUT_FILE.nocolor
rm ${OUTPUT_FILE}
OUTPUT_FILE=${OUTPUT_FILE}.nocolor

# Parse output and count PASS and FAIL messages
total=$(grep ' TOTAL:' "${OUTPUT_FILE}" | cut -d':' -f2 | tr -d ' ' | tr -d '\n' | tr -d '\r')
pass=$(grep ' PASS:' "${OUTPUT_FILE}"   | cut -d':' -f2 | tr -d ' ' | tr -d '\n' | tr -d '\r')
skip=$(grep ' SKIP:' "${OUTPUT_FILE}"   | cut -d':' -f2 | tr -d ' ' | tr -d '\n' | tr -d '\r')
fail=$(grep ' FAIL:' "${OUTPUT_FILE}"   | cut -d':' -f2 | tr -d ' ' | tr -d '\n' | tr -d '\r')
error=$(grep ' ERROR:' "${OUTPUT_FILE}" | cut -d':' -f2 | tr -d ' ' | tr -d '\n' | tr -d '\r')

#xfail=$(grep ' XFAIL:' "${OUTPUT_FILE}" | cut -d':' -f2 | tr -d ' ')
#xpass=$(grep ' XPASS:' "${OUTPUT_FILE}" | cut -d':' -f2 | tr -d ' ')

# extract minutes and seconds. Assuming no days
duration=$(grep -Po 'real\x09+\K[0-9dms.]*' ${OUTPUT_FILE})
minutes="${duration%m*}"
seconds="${duration#*m}"
seconds="${seconds%s}"

# convert to seconds
real_s=$(echo "$minutes * 60 + $seconds" | bc)

h=$(git rev-parse --short HEAD)

echo "#RAN AT $(date)"                                       | tee -a results_${h}.txt
echo "#QEMU ARGS: $1"                                        | tee -a results_${h}.txt
echo "#COMMAND: $2"                                          | tee -a results_${h}.txt
echo "RESULT: $total, $pass, $skip, $fail, $error, $real_s " | tee -a results_${h}.txt
echo ""                                                      | tee -a results_${h}.txt

echo "Finished in ${real_s} seconds"

rm ${OUTPUT_FILE}
