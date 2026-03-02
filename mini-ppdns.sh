#!/bin/sh
PROG="/usr/sbin/mini-ppdns"
CONF="/etc/mini-ppdns.ini"
PIDFILE="/tmp/mini-ppdns.pid"

is_running() {
	pidof mini-ppdns >/dev/null 2>&1 && return 0
	ps -ef | grep "mini-ppdns" | grep "config" >/dev/null 2>&1 && return 0
	return 1
}

get_cur_pid() {
	_cur_pid=$(pidof mini-ppdns 2>/dev/null)
	if [ -z "$_cur_pid" ]; then
		_cur_pid=$(ps -ef | grep "mini-ppdns" | grep "config" | head -n 1 | cut -d" " -f1)
	fi
	echo "$_cur_pid"
}

read_pidfile() {
	_saved_pid=""
	_saved_time=""
	if [ -f "$PIDFILE" ]; then
		_saved_pid=$(head -n 1 "$PIDFILE")
		_saved_time=$(tail -n 1 "$PIDFILE")
	fi
}

write_pidfile() {
	_pid=$(get_cur_pid)
	_time=$(date "+%Y-%m-%d %H:%M:%S")
	echo "$_pid" > "$PIDFILE"
	echo "$_time" >> "$PIDFILE"
}

remove_pidfile() {
	rm -f "$PIDFILE"
}

start() {
	if is_running; then
		read_pidfile
		_cur_pid=$(get_cur_pid)
		if [ -n "$_saved_pid" ] && [ "$_saved_pid" = "$_cur_pid" ]; then
			echo "mini-ppdns running OK. (started at: $_saved_time)"
		else
			echo "mini-ppdns running OK."
		fi
		exit 0
	fi

	if [ ! -x "$PROG" ]; then
		echo "Error: $PROG not found or not executable."
		exit 1
	fi

	"$PROG" -config "$CONF" -d
	sleep 1
	write_pidfile
	echo "mini-ppdns started."
}

stop() {
	if killall mini-ppdns >/dev/null 2>&1; then
		remove_pidfile
		echo "mini-ppdns all stopped."
		return
	fi
	_pid=$(pidof mini-ppdns)
	if [ -n "$_pid" ]; then
		echo "find mini-ppdns pid: $_pid"
		kill $_pid
		remove_pidfile
		echo "mini-ppdns stopped."
		return
	fi
	_pid=$(ps -ef | grep "mini-ppdns" | grep "config" | head -n 1 | cut -d" " -f1)
	if [ -n "$_pid" ]; then
		echo "find mini-ppdns pid: $_pid"
		kill "$_pid"
		remove_pidfile
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
