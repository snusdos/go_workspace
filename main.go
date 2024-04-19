package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	//logURI          string	moved
	pubKey     string
	getFirst   int64
	getLast    int64
	chainOut   bool
	textOut    bool
	crlOut     bool
	preOut     bool
	outputFile *os.File
	maxEntries int64
	lock       sync.Mutex
)

/*
TODO:
 1. implement way to increase entries gotten for each log
    1.1 ex by repeating 255 gotten untill certain number of index for each log reached
*/
func main() {
	ctx := context.Background()
	var wg sync.WaitGroup // WaitGroup to manage concurrency

	// Open output file
	var err error
	outputFile, err = os.Create("data/output.txt")
	if err != nil {
		klog.Exitf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Read logURIs from a file
	file, err := os.Open("data/input.txt")
	if err != nil {
		klog.Exitf("Failed to read log URI file: %v", err)
	}
	defer file.Close()

	skipHTTPSVerify = true // Skip verification of chain and hostname or not
	chainOut = false       // Entire chain or only end/leaf in output
	textOut = true         // .pem or .txt output
	crlOut = true          // print only crl of cert. textout must be true
	preOut = true          //include pres or not
	getFirst = 0           // First index
	getLast = 256          // Last index
	maxEntries = 10000000  //set max amount of entries for each log

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logURI := scanner.Text()
		fmt.Printf("Running Log: %s\n", logURI)
		wg.Add(1)             // Increment the WaitGroup counter
		go func(uri string) { // GO routine feeding rGE with logURI to allow concurr
			defer wg.Done()         // Decrement the counter when the goroutine completes
			runGetEntries(ctx, uri) // Pass logURI to the goroutine
		}(logURI)
	}

	if err := scanner.Err(); err != nil {
		klog.Errorf("Error reading URIs: %v", err)
	}

	wg.Wait() // Wait for all goroutines to finish
}

func runGetEntries(ctx context.Context, logURI string) {
	logClient := connect(ctx, logURI)
	index := int64(0)
	dynInt := int64(256)
	for index < maxEntries {
		getFirst := index
		getLast := index + dynInt - 1

		if getLast >= maxEntries {
			getLast = maxEntries - 1
		}

		rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
		if err != nil {
			fmt.Println("ERROR FROM: \n", logURI)
			//exitWithDetails(err)
			index += dynInt
			continue
		}

		entriesReturned := int64(len(rsp.Entries))
		if entriesReturned == 0 { // No more entries to process
			break
		}

		for i, rawEntry := range rsp.Entries {
			rleindex := getFirst + int64(i)
			rle, err := ct.RawLogEntryFromLeaf(rleindex, &rawEntry)
			if err != nil {
				fmt.Fprintf(outputFile, "Index=%d Failed to unmarshal leaf entry: %v\n", index, err)
				continue
			}
			showRawLogEntry(rle)
		}
		index += entriesReturned      //update index based off actual entries returned
		if entriesReturned < dynInt { //check for
			dynInt = entriesReturned
		}

	}
}

func showRawLogEntry(rle *ct.RawLogEntry) {
	ts := rle.Leaf.TimestampedEntry
	//when := ct.TimestampToTime(ts.Timestamp)
	//lock.Lock()
	//fmt.Fprintf(outputFile, "Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)
	//lock.Unlock()
	switch ts.EntryType {
	case ct.X509LogEntryType:
		//fmt.Fprintf(outputFile, "X.509 certificate:\n")
		showRawCert(*ts.X509Entry)

	case ct.PrecertLogEntryType:
		if preOut {
			//fmt.Fprintf(outputFile, "pre-certificate from issuer with keyhash %x:\n", ts.PrecertEntry.IssuerKeyHash)
			showRawCert(rle.Cert)
		}
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
	if crlOut {
		if len(cert.CRLDistributionPoints) > 0 {
			lock.Lock()
			fmt.Fprintf(outputFile, "%s\n", cert.CRLDistributionPoints[0])
			lock.Unlock()
		}
	} else if textOut {
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
