package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"k8s.io/klog"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	pubKey          string
	//getFirst        int64
	//getLast         int64
	chainOut   bool
	textOut    bool
	preOut     bool
	outputFile *os.File
	//maxEntries int64
	lock sync.Mutex
)

/*
TODO:
0.1 control max number of outputs.
1. Go rutines inom varje log på olika index
2. fixa folders för entries för att hantera massa filer KANSKE? https://forums.codeguru.com/showthread.php?390838-How-many-files-can-a-folder-contain
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
	file, err := os.Open("data/argonset.txt") //subset/input/whatever prob subset tho since so fucking much copies else.xd
	if err != nil {
		klog.Exitf("Failed to read log URI file: %v", err)
	}
	defer file.Close()

	skipHTTPSVerify = true // Skip verification of chain and hostname or not
	chainOut = false       // Entire chain or only end/leaf in output
	textOut = false        // .pem or .txt output
	preOut = false         //include pres or not
	//getFirst = 0            // First index	unsused
	//getLast = 256           // Last index unsused
	//maxEntries = 10000 //set max amount of entries to get in total

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

/*
TODO: fix so it ends after max entires is ok
*/
func runGetEntries(ctx context.Context, logURI string) {

	var logReturnedEntries int64

	logClient := connect(ctx, logURI)

	sth, err := logClient.GetSTH(ctx) //getSTH to get TreeSize for k
	if err != nil {
		fmt.Println("STH ERROR FROM: ", logURI)
	}
	fmt.Printf("STH: %v\n", sth.TreeSize)
	treeSize := sth.TreeSize
	entriesPerLog := math.Floor(0.01 * float64(treeSize)) //SET % TO QUERY FROM LOG 1% should be around 50m Leafs

	bar := progressbar.NewOptions64(
		int64(entriesPerLog),
		progressbar.OptionSetDescription("Processing log: "+logURI),
		progressbar.OptionSetWriter(os.Stderr), // Display progress in the standard error to avoid mixing with other output
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowIts(),
		progressbar.OptionSpinnerType(14),
	)

	//fmt.Printf("entreisPerLog: %v", entriesPerLog)
	for logReturnedEntries < int64(entriesPerLog) {
		getFirst := calcRand(int64(treeSize)) //random sampling
		getLast := getFirst + 999             //always get max/999 new entires
		rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
		if err != nil {
			fmt.Fprintf(outputFile, "GetRawEntries Error: %s From: %s \n", err, logURI)
			exitWithDetails(err)
			return //RETURN to kill routine
		}

		entriesReturned := int64(len(rsp.Entries))
		if entriesReturned == 0 { // No more entries to process prob trash now
			fmt.Fprintf(outputFile, "entriesReturned == 0 for logURI: %s \n", logURI)
			break
		}

		for i, rawEntry := range rsp.Entries {
			rleindex := getFirst + int64(i)
			rle, err := ct.RawLogEntryFromLeaf(rleindex, &rawEntry)
			if err != nil {
				fmt.Fprintf(outputFile, "Index=%d Failed to unmarshal leaf entry: %v\n", rleindex, err)
				continue
			}
			showRawLogEntry(rle)
		}
		logReturnedEntries += entriesReturned
		//index += entriesReturned //update index based off actual entries returned
		//k := int64(calcK(int64(treeSize)))
		//index += int64(calcK(int64(treeSize))) //int64))
		//fmt.Printf("K : %v\n", int64(calcK(int64(treeSize))))
		bar.Set64(logReturnedEntries) //update progbar
	}
	fmt.Fprintf(outputFile, "logURI: %s Finished at: %s Total Entries: %v \n", logURI, time.Now(), logReturnedEntries)
	bar.Finish()
}

func showRawLogEntry(rle *ct.RawLogEntry) {
	ts := rle.Leaf.TimestampedEntry          //timestamp
	when := ct.TimestampToTime(ts.Timestamp) //translation of ts
	//msts := ts.Timestamp                     //millisecond timestamp
	//mstsTime := millisToTime(int64(msts))    //just the ms timestamp
	//year, week := mstsTime.ISOWeek()         //ISOWeek setup
	//if week == 6 || week == 32 {             //only catch certs stamped within week 6 and 32.

	tsfilename := when.Format("20060102150405") // Format timestamp as YYYYMMDD

	switch ts.EntryType {
	case ct.X509LogEntryType:
		//lock.Lock()
		//fmt.Fprintf(outputFile, "Index=%d, year=%d, week=%d Timestamp=%d (%v) LOG=%s \n", rle.Index, year, week, ts.Timestamp, when, logURI)
		//lock.Unlock()
		//fmt.Fprintf(outputFile, "X.509 certificate:\n")
		//fmt.Fprintf(outputFile, "Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)
		showRawCert(*ts.X509Entry, tsfilename)

	case ct.PrecertLogEntryType:
		if preOut {
			//lock.Lock()
			//fmt.Fprintf(outputFile, "Index=%d year=%d  Timestamp=%d (%v) LOG=%s \n", rle.Index, year, ts.Timestamp, when, logURI)
			//lock.Unlock()
			showRawCert(rle.Cert, tsfilename)
		}
	default:
		fmt.Fprintf(outputFile, "Unhandled log entry type %d\n", ts.EntryType)
	}
	if chainOut {
		for _, c := range rle.Chain {
			showRawCert(c, tsfilename)
		}
	}
}

func showRawCert(cert ct.ASN1Cert, timestamp string) {

	if textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			klog.Errorf("Error parsing certificate: %q", err.Error())
		}
		if c == nil {
			return
		}
		showParsedCert(c, timestamp)
	} else {
		showPEMData(cert.Data, timestamp)
	}
}

func showParsedCert(cert *x509.Certificate, timestamp string) { //change so that if chainOut 1 chain file, if not no chain files

	serialNumber := fmt.Sprintf("%x", cert.SerialNumber) // Convert serial number to hex string
	fileName := fmt.Sprintf("/Volumes/A1/certificates/%s-%x.pem", timestamp, serialNumber)
	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)

	}
	defer sOutputFile.Close()

	certDetails := x509util.CertificateToString(cert)

	if textOut {
		if _, err := fmt.Fprintf(sOutputFile, "%s\n", certDetails); err != nil {
			fmt.Printf("Failed to write to file: %v\n", err)
			return
		}
		return
	}
	showPEMData(cert.Raw, timestamp)
}

func showPEMData(data []byte, timestamp string) {
	id := uuid.New()
	fileName := fmt.Sprintf("/Volumes/A1/certificates/%s_%s.pem", timestamp, id)
	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)
	}
	defer sOutputFile.Close()
	lock.Lock()
	if err := pem.Encode(sOutputFile, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		klog.Errorf("Failed to PEM encode cert: %q", err.Error())
	}
	lock.Unlock()
}

func calcRand(n int64) int64 {
	rnum := rand.Int63n(n)
	if rnum >= n-1000 { //if number generated is in top end routine might end
		return rnum - 1000
	}
	return rnum
}

/*
func calcK(n int64) float64 { //func to create a k val logaritmicly increasing
	var multiplier float64 = 3000
	var c float64 = -23000
	k := multiplier*math.Log10(float64(n)) + c //n wont be zero
	k = math.Floor(k)
	if k <= 0 {
		return 0
	} else {
		return k
	}
}

func millisToTime(ms int64) time.Time {
	return time.Unix(ms/1000, (ms%1000)*1000000)
}
*/
