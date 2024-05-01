# This will fill the result.csv file with the desired
# columns. Also fills in the headers.
# For performance reasons, this might be worth to do in 
# pemToTxt.sh and also using parallel.
#time bash ./tools/csvRankDomain.sh         
echo "Creating result.csv"
printf "fname\tserialnumber\tsubjectC\tsubjectCN\tsubjectL\tsubjectO\tsubjectOU\tissuerC\tissuerCN\tissuerL\tissuerO\tissuerOU\ttypeOfCert\tSCTs\tsignatureAlgorithm\tpublicKeyAlgorithm\tCRL\tOCSP\tvalidity\tkeyLength\n" > result.csv

# Compile the C script
gcc -std=c99 tools/c_scripts/getBasics.c -O3 -o tools/c_scripts/getBasics

for f in data/text/*;
do
    basic_info=$(tools/c_scripts/getBasics "$f")
    base_filename="${f##*/}"
    fname="${base_filename%.txt}"
    printf "%s\t%s\t%s\n" "$fname" "$basic_info" >> result.csv
done
# Sorts the file in place numerically based on the first column
sort -k1 -n -o result.csv result.csv
echo "Finished filling result.csv"
