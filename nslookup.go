package nslookup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func ParseUint16(s string) (uint16, error) {
	if v, err := strconv.ParseUint(s, 10, 16); err != nil {
		return 0, err
	} else {
		return uint16(v), nil
	}
}

// An MX represents a single DNS MX record.
type MX struct {
	Pref uint16
	Host string
}

// An NS represents a single DNS NS record.
type NS struct {
	Host string
}

type NsLookup struct {
	cmd string
}

func NewNsLookup() *NsLookup {
	n := new(NsLookup)
	n.cmd = "/usr/bin/nslookup"

	if _, err := os.Stat(n.cmd); os.IsNotExist(err) {
		panic(fmt.Errorf("no such file or directory: %s", n.cmd))
	}
	return n
}

func (n *NsLookup) Lookup(domain, dnsType, dnsServer string) (io.Reader, error) {
	query := fmt.Sprintf("-q=%s", dnsType)
	cmd := exec.Command(n.cmd, query, domain, dnsServer)

	if cmd.Stdout != nil {
		return nil, errors.New("nslookup: Stdout already set")
	}
	if cmd.Stderr != nil {
		return nil, errors.New("nslookup: Stderr already set")
	}
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	err := cmd.Run()

	return &b, err
}

func (n *NsLookup) LookupNS(domain, dnsServer string) (ns []*NS, err error) {
	out, err := n.Lookup(domain, "ns", dnsServer)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		token := scanner.Text()
		if strings.Contains(token, "nameserver =") {
			host := strings.TrimSpace(strings.Split(token, "=")[1])
			ns = append(ns, &NS{host})
		}
	}

	return
}

func (n *NsLookup) LookupMX(domain, dnsServer string) (mx []*MX, err error) {
	out, err := n.Lookup(domain, "mx", dnsServer)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		token := scanner.Text()
		if strings.Contains(token, "mail exchanger =") {
			data := strings.TrimSpace(strings.Split(token, "=")[1])
			f := strings.Split(data, " ")
			if pref, err := ParseUint16(f[0]); err == nil {
				mx = append(mx, &MX{pref, f[1]})
			}
		}
	}

	return
}

func (n *NsLookup) LookupTXT(domain, dnsServer string) (txt []string, err error) {
	out, err := n.Lookup(domain, "txt", dnsServer)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		token := scanner.Text()
		if strings.Contains(token, "text =") {
			data := strings.TrimSpace(strings.Split(token, "=")[1])
			txt = append(txt, strings.Trim(data, "\""))
		}
	}

	return
}

//TODO: cname, etc
