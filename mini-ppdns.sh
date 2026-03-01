#!/bin/sh
PROG="/usr/sbin/mini-ppdns"
CONF="/etc/mini-ppdns.ini"

is_running() {
	pidof mini-ppdns >/dev/null 2>&1 && return 0
	ps -ef | grep "mini-ppdns" | grep "config" >/dev/null 2>&1 && return 0
	return 1
}

start() {
	if is_running; then
		echo "mini-ppdns running OK."
		exit 0
	fi

	if [ ! -x "$PROG" ]; then
		echo "Error: $PROG not found or not executable."
		exit 1
	fi
	"$PROG" -config "$CONF" -d
	echo "mini-ppdns started."
}

stop() {
	if killall mini-ppdns >/dev/null 2>&1; then
		echo "mini-ppdns all stopped."
		return
	fi
	_pid=$(pidof mini-ppdns)
	if [ -n "$_pid" ]; then
		echo "find mini-ppdns pid: $_pid"
		kill $_pid
		echo "mini-ppdns stopped."
		return
	fi
	_pid=$(ps -ef | grep "mini-ppdns" | grep "config" | head -n 1 | cut -d" " -f1)
	if [ -n "$_pid" ]; then
		echo "find mini-ppdns pid: $_pid"
		kill "$_pid"
		echo "mini-ppdns stopped."
		return
	fi
	echo "mini-ppdns is not running."
}

restart() {
	stop
	sleep 1
	start
}

case "$1" in
start)
	start
	;;
stop)
	stop
	;;
restart)
	restart
	;;
"")
	start
	;;
*)
	if [ "$1" = "mini-ppdns.sh" ]; then
		start
	else
		echo "Usage: $0 {start|stop|restart}"
		exit 1
	fi
	;;
esac
