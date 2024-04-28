package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog"
)

func exitWithDetails(err error) {
	if err, ok := err.(client.RspError); ok {
		klog.Infof("HTTP details: status=%d, body:\n%s", err.StatusCode, err.Body)
	}
	klog.Error(err.Error()) //klog.exit(err.Error())
}

func connect(_ context.Context, logURI string) *client.LogClient {
	var tlsCfg *tls.Config
	if skipHTTPSVerify {
		//klog.Warning("Skipping HTTPS connection verification")
		tlsCfg = &tls.Config{InsecureSkipVerify: skipHTTPSVerify}
	}
	httpClient := &http.Client{
		Timeout: 100 * time.Second, //10 was abit low
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100, //try with more
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsCfg,
		},
	}
	opts := jsonclient.Options{UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"} //try without 3min fast for 400k cert xenon2018 log.
	if pubKey != "" {
		pubkey, err := os.ReadFile(pubKey)
		if err != nil {
			klog.Exit(err)
		}
		opts.PublicKey = string(pubkey)
	}

	uri := logURI
	if logName != "" {
		llData, err := x509util.ReadFileOrURL(logList, httpClient)
		if err != nil {
			klog.Exitf("Failed to read log list: %v", err)
		}
		ll, err := loglist3.NewFromJSON(llData)
		if err != nil {
			klog.Exitf("Failed to build log list: %v", err)
		}

		logs := ll.FindLogByName(logName)
		if len(logs) == 0 {
			klog.Exitf("No log with name like %q found in loglist %q", logName, logList)
		}
		if len(logs) > 1 {
			logNames := make([]string, len(logs))
			for i, log := range logs {
				logNames[i] = fmt.Sprintf("%q", log.Description)
			}
			klog.Exitf("Multiple logs with name like %q found in loglist: %s", logName, strings.Join(logNames, ","))
		}
		uri = logs[0].URL
		if opts.PublicKey == "" {
			opts.PublicKeyDER = logs[0].Key
		}
	}

	klog.V(1).Infof("Use CT log at %s", uri)
	logClient, err := client.New(uri, httpClient, opts)
	if err != nil {
		klog.Exit(err)
	}

	return logClient
}
