# This will fill the result.csv file with the desired
# columns. Also fills in the headers.
# For performance reasons, this might be worth to do in 
# pemToTxt.sh and also using parallel.
echo "Creating result.csv"
printf "rank\tdomain\tserialnumber\tsubjectC\tsubjectCN\tsubjectL\tsubjectO\tsubjectOU\tissuerC\tissuerCN\tissuerL\tissuerO\tissuerOU\ttypeOfCert\tSCTs\tsignatureAlgorithm\tpublicKeyAlgorithm\tCRL\tOCSP\tvalidity\tkeyLength\tpolicyOID\tCPS\n" > result.csv

# Compile the C script
gcc -std=c99 scripts/c_scripts/getBasics.c -O3 -o scripts/c_scripts/getBasics

for f in data/text/*;
do
    policy=$(cat "$f" | bash scripts/bash_scripts/getPolicy.sh)
    cps=$(cat "$f" | bash scripts/bash_scripts/getCPS.sh)
    basic_info=$(scripts/c_scripts/getBasics "$f")
    base_filename="${f##*/}"
    IFS='-' read -r rank domain <<< $base_filename
    parsedUrl=${domain%.txt}
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$rank" "${domain%.txt}" "$basic_info" "$policy" "$cps" >> result.csv
done
# Sorts the file in place numerically based on the first column
sort -k1 -n -o result.csv result.csv
sort -k1 -n -o data/empty_domains.csv data/empty_domains.csv #sort empty aswell...
echo "Finished filling result.csv"
