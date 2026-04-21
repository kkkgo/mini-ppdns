package main

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kkkgo/mini-ppdns/mlog"
)

type ConfigArgs struct {
	DNS        []string
	Fall       []string
	Listen     []string
	ForceFall  []string
	QTime      int
	AAAA       string
	Lite       string
	TrustRcode []int // trusted rcodes from main DNS (e.g. 0,3)
	Daemon     bool
	Debug      bool

	LeaseFile    []string // DHCP lease files (e.g. /tmp/dhcp.leases)
	HostsFile    []string // hosts files (e.g. /etc/hosts)
	BogusPriv    bool     // return NXDOMAIN for private PTR queries not found locally
	BogusPrivSet bool     // whether boguspriv was explicitly set in config file

	PPLogUUID      string
	PPLogServer    string
	PPLogLevel     int
	PPLogHeartBeat int // seconds, 0 = disabled

	Hosts map[string][]net.IP // [hosts] section: domain -> IPs

	Hook *HookConfig
}

type HookConfig struct {
	Exec           string
	ExitCode       int
	ExitCodeSet    bool
	Keyword        string
	SleepTime      int // seconds, default 60
	RetryTime      int // seconds, default 5
	Count          int // consecutive failures before marking down, default 10
	SwitchFallExec string
	SwitchMainExec string
}

func parseINI(filename string, m *ConfigArgs, logger *mlog.Logger) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Raise the per-line cap above bufio.Scanner's 64 KiB default so a
	// [hosts] entry with many aliases doesn't trip ErrTooLong.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}

		switch section {
		case "dns":
			m.DNS = append(m.DNS, line)
		case "fall":
			m.Fall = append(m.Fall, line)
		case "listen":
			m.Listen = append(m.Listen, line)
		case "force_fall":
			m.ForceFall = append(m.ForceFall, line)
		case "adv":
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				switch k {
				case "qtime":
					if n, err := strconv.Atoi(v); err == nil {
						m.QTime = n
					} else {
						logger.Warnw("invalid qtime value, using default", mlog.String("value", v))
					}
				case "aaaa":
					m.AAAA = v
				case "lite":
					m.Lite = v
				case "trust_rcode":
					m.TrustRcode = nil
					for _, s := range strings.Split(v, ",") {
						s = strings.TrimSpace(s)
						if s == "" {
							continue
						}
						if n, err := strconv.Atoi(s); err == nil {
							m.TrustRcode = append(m.TrustRcode, n)
						} else {
							logger.Warnw("invalid trust_rcode value, skipping", mlog.String("value", s))
						}
					}
				case "boguspriv":
					m.BogusPriv = v == "1" || v == "yes" || v == "true"
					m.BogusPrivSet = true
				case "lease_file":
					for _, lf := range strings.Split(v, ",") {
						lf = strings.TrimSpace(lf)
						if lf != "" {
							m.LeaseFile = append(m.LeaseFile, lf)
						}
					}
				case "hosts_file":
					for _, hf := range strings.Split(v, ",") {
						hf = strings.TrimSpace(hf)
						if hf != "" {
							m.HostsFile = append(m.HostsFile, hf)
						}
					}
				}
			}
		case "hosts":
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[0])
				if ip == nil {
					logger.Warnw("invalid hosts IP, skipping", mlog.String("line", line))
					continue
				}
				if m.Hosts == nil {
					m.Hosts = make(map[string][]net.IP)
				}
				for _, domain := range fields[1:] {
					domain = strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
					m.Hosts[domain] = append(m.Hosts[domain], ip)
				}
			}
		case "pplog":
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.TrimSpace(kv[1])
				switch k {
				case "uuid":
					m.PPLogUUID = v
				case "server":
					m.PPLogServer = v
				case "level":
					if n, err := strconv.Atoi(v); err == nil {
						m.PPLogLevel = n
					} else {
						logger.Warnw("invalid pplog level value, using default", mlog.String("value", v))
					}
				case "heart_beat":
					if n, err := strconv.Atoi(v); err == nil && n >= 0 {
						m.PPLogHeartBeat = n
					} else {
						logger.Warnw("invalid pplog heart_beat value, ignoring", mlog.String("value", v))
					}
				}
			}
		case "hook":
			kv := strings.SplitN(line, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(kv[0])
				v := strings.Trim(strings.TrimSpace(kv[1]), "\"")
				if m.Hook == nil {
					m.Hook = &HookConfig{SleepTime: 60, RetryTime: 5, Count: 10}
				}
				switch k {
				case "exec":
					m.Hook.Exec = v
				case "exit_code":
					if n, err := strconv.Atoi(v); err == nil {
						m.Hook.ExitCode = n
						m.Hook.ExitCodeSet = true
					} else {
						logger.Warnw("invalid hook exit_code value", mlog.String("value", v))
					}
				case "keyword":
					m.Hook.Keyword = v
				case "sleep_time":
					if n, err := strconv.Atoi(v); err == nil && n > 0 {
						m.Hook.SleepTime = n
					} else {
						logger.Warnw("invalid hook sleep_time value, using default", mlog.String("value", v))
					}
				case "retry_time":
					if n, err := strconv.Atoi(v); err == nil && n > 0 {
						m.Hook.RetryTime = n
					} else {
						logger.Warnw("invalid hook retry_time value, using default", mlog.String("value", v))
					}
				case "count":
					if n, err := strconv.Atoi(v); err == nil && n > 0 {
						m.Hook.Count = n
					} else {
						logger.Warnw("invalid hook count value, using default", mlog.String("value", v))
					}
				case "switch_fall_exec":
					m.Hook.SwitchFallExec = v
				case "switch_main_exec":
					m.Hook.SwitchMainExec = v
				}
			}
		}
	}
	return scanner.Err()
}
