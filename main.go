package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	logURI          string
	pubKey          string
	getFirst        int64
	getLast         int64
	chainOut        bool
	textOut         bool
	outputFile      *os.File
)

func main() {
	ctx := context.Background()

	// Open output file
	var err error
	outputFile, err = os.Create("output.txt")
	if err != nil {
		klog.Exitf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Read logURIs from a file
	file, err := os.Open("input.txt")
	if err != nil {
		klog.Exitf("Failed to read log URI file: %v", err)
	}
	defer file.Close()

	skipHTTPSVerify = true // Skip verification of chain and hostname or not
	chainOut = true        // Entire chain or only end/leaf in output
	textOut = false        // .pem or .txt output
	getFirst = 0           // First index
	getLast = 0            // Last index

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logURI = scanner.Text()
		fmt.Printf("Running Log: %s\n", logURI)
		runGetEntries(ctx)
	}

	if err := scanner.Err(); err != nil {
		klog.Errorf("Error reading URIs: %v", err)
	}
}

func runGetEntries(ctx context.Context) {
	logClient := connect(ctx)
	if getFirst == -1 {
		klog.Exit("No -first option supplied")
	}
	if getLast == -1 {
		getLast = getFirst
	}
	rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
	if err != nil {
		exitWithDetails(err)
	}

	for i, rawEntry := range rsp.Entries {
		index := getFirst + int64(i)
		rle, err := ct.RawLogEntryFromLeaf(index, &rawEntry)
		if err != nil {
			fmt.Fprintf(outputFile, "Index=%d Failed to unmarshal leaf entry: %v\n", index, err)
			continue
		}
		showRawLogEntry(rle)
	}
}

func showRawLogEntry(rle *ct.RawLogEntry) {
	ts := rle.Leaf.TimestampedEntry
	when := ct.TimestampToTime(ts.Timestamp)
	fmt.Fprintf(outputFile, "Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)

	switch ts.EntryType {
	case ct.X509LogEntryType:
		fmt.Fprintf(outputFile, "X.509 certificate:\n")
		showRawCert(*ts.X509Entry)
	case ct.PrecertLogEntryType:
		fmt.Fprintf(outputFile, "pre-certificate from issuer with keyhash %x:\n", ts.PrecertEntry.IssuerKeyHash)
		showRawCert(rle.Cert)
	default:
		fmt.Fprintf(outputFile, "Unhandled log entry type %d\n", ts.EntryType)
	}
	if chainOut {
		for _, c := range rle.Chain {
			showRawCert(c)
		}
	}
}

func showRawCert(cert ct.ASN1Cert) {
	if textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			klog.Errorf("Error parsing certificate: %q", err.Error())
		}
		if c == nil {
			return
		}
		showParsedCert(c)
	} else {
		showPEMData(cert.Data)
	}
}

func showParsedCert(cert *x509.Certificate) { //change so that if chainOut 1 chain file, if not no chain files
	if textOut {
		fmt.Fprintf(outputFile, "%s\n", x509util.CertificateToString(cert))
	} else {
		showPEMData(cert.Raw)
	}
}

func showPEMData(data []byte) {
	if err := pem.Encode(outputFile, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		klog.Errorf("Failed to PEM encode cert: %q", err.Error())
	}
}
