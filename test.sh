#!/bin/bash
set -e

echo "Building mini-ppdns..."
go build -o mini-ppdns .

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

SUCCESS=0
FAIL=0

function run_test() {
	local name=$1
	local safe_name=${name// /_}
	local cmd=$2
	local query=$3
	local expected=$4
	local port=$5

	echo -n "Test [$name]... "

	eval "$cmd > server_${safe_name}.log 2>&1 &"
	local pid=$!

	sleep 1

	set +e
	local result=$(dig @127.0.0.1 -p $port $query +short)
	set -e

	if echo "$result" | grep -q "$expected"; then
		echo -e "${GREEN}PASS${NC}"
		SUCCESS=$((SUCCESS + 1))
	else
		echo -e "${RED}FAIL${NC}"
		echo "Expected: $expected"
		echo "Got: $result"
		echo "Server log:"
		cat "server_${safe_name}.log"
		FAIL=$((FAIL + 1))
	fi

	kill $pid 2>/dev/null || true
	wait $pid 2>/dev/null || true
	rm -f "server_${safe_name}.log"
}

echo "Running tests..."

# 1. Basic fallback test
run_test "Basic" "./mini-ppdns -dns 6.6.6.6 -fall 1.1.1.1 -listen 127.0.0.1:5353" "example.com A" "[0-9]" 5353

# 2. Multi-upstream test
run_test "Multi-upstream" "./mini-ppdns -dns 8.8.8.8,8.8.4.4 -fall 1.1.1.1,1.0.0.1 -listen 127.0.0.1:5354" "example.com A" "[0-9]" 5354

# 3. AAAA block test (default)
echo -n "Test [AAAA block]... "
./mini-ppdns -dns 8.8.8.8 -fall 1.1.1.1 -listen 127.0.0.1:5355 -debug >server_aaaa.log 2>&1 &
pid=$!
sleep 1
set +e
result=$(dig @127.0.0.1 -p 5355 example.com AAAA +short)
set -e
if grep -q "BLOCKED" server_aaaa.log; then
	echo -e "${GREEN}PASS${NC}"
	SUCCESS=$((SUCCESS + 1))
else
	echo -e "${RED}FAIL${NC}"
	echo "Expected log 'BLOCKED', got:"
	cat server_aaaa.log
	FAIL=$((FAIL + 1))
fi
kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true
rm -f server_aaaa.log

# 4. AAAA allow test
echo -n "Test [AAAA allow]... "
./mini-ppdns -dns 8.8.8.8 -fall 1.1.1.1 -listen 127.0.0.1:5356 -aaaa=yes -debug >server_aaaa_allow.log 2>&1 &
pid=$!
sleep 1
set +e
result=$(dig @127.0.0.1 -p 5356 example.com AAAA +short)
set -e
if grep -q "local ->" server_aaaa_allow.log && ! grep -q "BLOCKED" server_aaaa_allow.log; then
	echo -e "${GREEN}PASS${NC}"
	SUCCESS=$((SUCCESS + 1))
else
	echo -e "${RED}FAIL${NC}"
	echo "Expected upstream query log without block, got:"
	cat server_aaaa_allow.log
	FAIL=$((FAIL + 1))
fi
kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true
rm -f server_aaaa_allow.log

# 5. Config file test
cat <<EOF >test_config.ini
[dns]
8.8.8.8:53
[fall]
1.1.1.1:53
[listen]
127.0.0.1:5357
[adv]
qtime=100
aaaa=no
EOF
run_test "Config file" "./mini-ppdns -config test_config.ini" "example.com A" "[0-9]" 5357
rm -f test_config.ini

echo ""
echo "Tests Passed: $SUCCESS"
echo "Tests Failed: $FAIL"

if [ $FAIL -gt 0 ]; then
	exit 1
fi
exit 0
