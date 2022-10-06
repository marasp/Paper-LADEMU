#!/bin/bash

infile=$1 # pcap logfile

label_cut_pcaps() {
  files_to_loop=$(find "./tempFiles"  -name "file*.txt" | sort)
  i=0

  for f in $files_to_loop; do

    printf "$f round of comments:"
    i=$((i+1))

    finalEditcapString=""
    concatString=""

    COUNTER=0
    while IFS= read -r line; do
       concatString+=$line
       COUNTER=$[$COUNTER +1]
       printf "$COUNTER ** $f \n"
       finalEditcapString=$concatString
    done < "$f"

    COUNTER=$[$COUNTER +1]

    firstNumber=$(head -n1 $f | cut -d ":" -f1 | cut -d " " -f2)
    lastNumber=$(tail -n1 $f | cut -d ":" -f1 | cut -d " " -f2)
    lastCommentText=$(tail -n1 $f | cut -d ":" -f2)

    lastComment="-a $lastNumber:$lastCommentText" # Adding the last line of the file, it was lost somehow
    finalEditcapString+=$lastComment
    editcap $finalEditcapString -r $infile "tempFiles/$i.pcapng" $firstNumber-$lastNumber
    rm $f
  done

}

# Call to run the functions
label_cut_pcaps



