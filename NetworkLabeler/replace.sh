#!/bin/bash

csvfile=$1
jsonfile=$3


# 1 = the file you want to edit
# 2 = what you want to add instead of blank entry
for i in $( seq 1 2); do
  sed -e "s/^|/$2|/" -e "s/||/|$2|/g" -e "s/|$/|$2/" -i $1
done

# change frame.comment to label in csv file:
sed -i 's/frame.comment/label/g' $csvfile
# change info column that made Pandas interpret one column too much:
sed -i 's/ "<ROOT>"  | searchResDone/ "<ROOT>"   searchResDonelabel/g' $csvfile

# change pkt_comment and frame.comment in json file:
sed -i 's/pkt_comment/pkt_label/g' $jsonfile
sed -i 's/frame.comment/label/g' $jsonfile