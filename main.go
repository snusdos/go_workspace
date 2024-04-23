package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	pubKey          string
	getFirst        int64
	getLast         int64
	chainOut        bool
	textOut         bool
	crlOut          bool
	preOut          bool
	sOutputFile     *os.File
	outputFile      *os.File
	maxEntries      int64
	lock            sync.Mutex
	incInt          int64
)

/*
TODO:
0. fix kill on max entries for tree.
1. create map, save hex values to elim dupes.
2. fixa folders för entries för att hantera massa filer KANSKE? https://forums.codeguru.com/showthread.php?390838-How-many-files-can-a-folder-contain
3. clean up
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
	file, err := os.Open("data/subset.txt") //subset/input/whatever prob subset tho since so fucking much copies else.xd
	if err != nil {
		klog.Exitf("Failed to read log URI file: %v", err)
	}
	defer file.Close()

	skipHTTPSVerify = true // Skip verification of chain and hostname or not
	chainOut = false       // Entire chain or only end/leaf in output
	textOut = true         // .pem or .txt output
	crlOut = false         // print only crl of cert. textout must be true
	preOut = false         //include pres or not
	getFirst = 0           // First index	unsused
	getLast = 256          // Last index unsused
	maxEntries = 1000      //set max amount of entries for each log

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
	dynInt := int64(1000) //start val for dynInt
	for index < maxEntries {
		getFirst := index
		getLast := index + dynInt - 1

		if getLast >= maxEntries { //trash needs remake but not important
			getLast = maxEntries - 1
		}

		rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
		if err != nil {
			fmt.Println("ERROR FROM: ", logURI)
			fmt.Println(err)
			exitWithDetails(err)
			index += dynInt
			return //RETURN OR CONTINUE need kill rutine here
		}

		entriesReturned := int64(len(rsp.Entries))
		fmt.Printf("entriesReturned: %v LOG: %s", entriesReturned, logURI)
		fmt.Println("getLast: ", getLast)
		fmt.Println("dynInt: ", dynInt)
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
			showRawLogEntry(rle, logURI)
		}
		index += entriesReturned      //update index based off actual entries returned
		if entriesReturned < dynInt { //check for
			dynInt = entriesReturned
		}

	}
}

func showRawLogEntry(rle *ct.RawLogEntry, logURI string) {
	ts := rle.Leaf.TimestampedEntry          //timestamp
	when := ct.TimestampToTime(ts.Timestamp) //translation of ts
	msts := ts.Timestamp                     //millisecond timestamp
	mstsTime := millisToTime(int64(msts))    //just the ms timestamp
	year, week := mstsTime.ISOWeek()         //ISOWeek setup
	if week == 6 || week == 32 {             //only catch certs stamped within week 6 and 32.
		//fmt.Printf("year%d Index=%d Timestamp=%d (%v) ", year, rle.Index, ts.Timestamp, when)

		switch ts.EntryType {
		case ct.X509LogEntryType:
			lock.Lock()
			fmt.Fprintf(outputFile, "Index=%d year=%d  Timestamp=%d (%v) LOG=%s \n", rle.Index, year, ts.Timestamp, when, logURI)
			lock.Unlock()
			//fmt.Fprintf(outputFile, "X.509 certificate:\n")
			//fmt.Fprintf(outputFile, "Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)
			showRawCert(*ts.X509Entry)

		case ct.PrecertLogEntryType:
			if preOut {
				lock.Lock()
				fmt.Fprintf(outputFile, "Index=%d year=%d  Timestamp=%d (%v) LOG=%s \n", rle.Index, year, ts.Timestamp, when, logURI)
				lock.Unlock()
				//fmt.Fprintf(outputFile, "pre-certificate from issuer with keyhash %x:\n", ts.PrecertEntry.IssuerKeyHash)
				//fmt.Fprintf(outputFile, "Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)
				showRawCert(rle.Cert)
			}
		default:
			fmt.Fprintf(outputFile, "Unhandled log entry type %d\n", ts.EntryType)
		}
		fmt.Println("")
		if chainOut {
			for _, c := range rle.Chain {
				showRawCert(c)
			}
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

	lock.Lock()
	defer lock.Unlock()
	fileName := fmt.Sprintf("e:/certslol/%x.pem", cert.SerialNumber)
	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)

	}
	defer sOutputFile.Close()

	certDetails := x509util.CertificateToString(cert)

	if crlOut {
		if len(cert.CRLDistributionPoints) > 0 {
			//lock.Lock()
			//fmt.Fprintf(outputFile, "%s\n", cert.CRLDistributionPoints[0])
			//lock.Unlock()
		}
	} else if textOut {

		if _, err := fmt.Fprintf(sOutputFile, "%s\n", certDetails); err != nil {
			fmt.Printf("Failed to write to file: %v\n", err)
			return
		}

		//fmt.Printf("formatted= %x \n", cert.SerialNumber)
		//fmt.Fprintf(outputFile, "%s\n", x509util.CertificateToString(cert))
	} else {
		showPEMData(cert.Raw)
	}
}

func showPEMData(data []byte) {

	lock.Lock()
	defer lock.Unlock()
	fileName := fmt.Sprintf("e:/certslol/%d.pem", incInt)
	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)
	}
	defer sOutputFile.Close()

	if err := pem.Encode(sOutputFile, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		klog.Errorf("Failed to PEM encode cert: %q", err.Error())
	}
	incInt++
}

func millisToTime(ms int64) time.Time {
	return time.Unix(ms/1000, (ms%1000)*1000000)
}
