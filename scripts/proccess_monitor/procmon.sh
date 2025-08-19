#!/bin/bash
old_procs=$(ps -eo user,command)

while true; do
	new_procs=$(ps -eo user,command)
	diff <(echo "$old_procs") <(echo "$new_procs") | grep "[\>\<]" | grep -vE "procmon|command|kworker"
	old_procs=$new_procs
done
