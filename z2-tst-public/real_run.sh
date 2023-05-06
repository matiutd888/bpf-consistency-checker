./run.sh >dupa
echo "############################################################"
cat dupa | grep -v "\[MATI\]" | grep -v "custom load buffer"