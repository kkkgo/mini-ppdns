#!/bin/sh
PROG="/usr/sbin/mini-ppdns"
CONF="/etc/mini-ppdns.ini"
PIDFILE="/tmp/mini-ppdns.pid"

is_running() {
	pidof mini-ppdns >/dev/null 2>&1 && return 0
	for _pid_dir in /proc/[0-9]*; do
		[ -r "$_pid_dir/exe" ] || continue
		if [ "$(readlink "$_pid_dir/exe")" = "$PROG" ]; then
			return 0
		fi
	done
	return 1
}

get_cur_pid() {
	_cur_pid=$(pidof mini-ppdns 2>/dev/null)
	if [ -z "$_cur_pid" ]; then
		for _pid_dir in /proc/[0-9]*; do
			[ -r "$_pid_dir/exe" ] || continue
			if [ "$(readlink "$_pid_dir/exe")" = "$PROG" ]; then
				_pid=$(basename "$_pid_dir")
				if [ -n "$_cur_pid" ]; then
					_cur_pid=""
					break
				fi
				_cur_pid="$_pid"
			fi
		done
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
	echo "$_pid" >"$PIDFILE"
	echo "$_time" >>"$PIDFILE"
}

remove_pidfile() {
	rm -f "$PIDFILE"
}

start() {
	if is_running; then
		read_pidfile
		_cur_pid=$(get_cur_pid)
		if [ -n "$_saved_pid" ] && [ "$_saved_pid" = "$_cur_pid" ]; then
			echo "mini-ppdns running OK. (started at: $_saved_time) PID: $_cur_pid"
		else
			echo "mini-ppdns running OK. PID: $_cur_pid"
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
	if ! is_running; then
		remove_pidfile
		echo "mini-ppdns is not running."
		return
	fi
	killall mini-ppdns >/dev/null 2>&1
	_i=0
	while is_running && [ "$_i" -lt 8 ]; do
		sleep 1
		_i=$((_i + 1))
	done
	if is_running; then
		echo "mini-ppdns did not stop in time, sending SIGKILL."
		killall -9 mini-ppdns >/dev/null 2>&1
		sleep 1
	fi
	remove_pidfile
	echo "mini-ppdns stopped."
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
