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
	# Send SIGTERM to every instance, then WAIT for it to actually exit.
	# The daemon's graceful shutdown is capped at ~5s internally, so poll a
	# little longer before escalating. Without this wait, restart() would
	# relaunch while the old process is still draining (is_running still
	# true), start() would see it "running" and refuse to start, and nothing
	# would be left running once the old process finally exits.
	killall mini-ppdns >/dev/null 2>&1
	_i=0
	while is_running && [ "$_i" -lt 8 ]; do
		sleep 1
		_i=$((_i + 1))
	done
	# Escalate to SIGKILL if a wedged process refused SIGTERM, so a restart
	# can always reclaim the listen port instead of forcing a reboot.
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
