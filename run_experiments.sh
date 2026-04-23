#!/bin/bash
echo "VEILDRA Experiment Runner"
echo "========================="
echo ""
echo "Running 10 detection experiments from inside Mininet..."

for i in {1..10}
do
    echo "Experiment $i running..."
    sudo mn -c > /dev/null 2>&1
    echo "h2 nmap -sS --min-rate 5000 -p 3306,5432,27017,6379,1433,1521,3306,5432,3306,5432,27017,6379 10.0.0.1" | sudo timeout 30 python3 -c "
import subprocess
import sys
result = subprocess.run(['sudo', 'mnexec', '-a', '2', 'nmap', '-sS', '--min-rate', '5000', '-p', '3306,5432,27017,6379,1433', '10.0.0.1'], capture_output=True)
print(result.stdout.decode())
"
    echo "Experiment $i done. Waiting 8 seconds..."
    sleep 8
done
