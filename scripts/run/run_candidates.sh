#!/usr/bin/env bash

function at_exit {
    if [ "$?" -ne 0 ] # print usage if script quit with error code
    then
        # e.g. bash run_candidates.sh 240000 /root/thesis/data/alexa_cpy_results_non-strictly_inc /root/thesis 10000
        echo "Usage: $0 <ENDVALUE> <DATA_DIR> [<EXECUTABLE_DIR> <INTERVAL>]"
        exit 1
    fi

    exit 0
}

trap at_exit EXIT # execute function at any kind of exit

set -u # Treat unset variables as an error when substituting

DATADIR=$2
if [ -z ${3+x} ] # https://stackoverflow.com/a/13864829
then
  EXE="ipsiblings/main.py"
  EXEDIR="ipsiblings"
else
  EXE="$3/ipsiblings/main.py"
  EXEDIR="$3/ipsiblings"
fi

if [ -z ${4+x} ] # https://stackoverflow.com/a/13864829
then
  INTERVAL=10000
else
  INTERVAL=${4}
fi


COUNTER=0
echo "$(/bin/date +"%Y-%m-%d %T") - Started"
NOW=$(/bin/date +"%Y-%m-%d_%H.%M.%S")

while [ $COUNTER -lt $1 ] # alexa resolved list: 231750
do
  let FROM=${COUNTER}
  let TO=${COUNTER}+${INTERVAL}
  # echo "$FROM - $TO - $DATADIR - $EXE - $INTERVAL"

  DIR="$DATADIR/alexa_$FROM-$TO"
  # DIR="$DATADIR/cisco_$FROM-$TO"
  echo "$(/bin/date +"%Y-%m-%d %T") - Processing range $FROM - $TO [$DIR] ..."

  mkdir -p ${DIR}
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -sf ${EXEDIR}/alexa_resolved.csv -r -vv --from ${FROM} --to ${TO} --server-ports --lowruntime > ${DIR}/out.log
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --from ${FROM} --to ${TO} --server-ports > ${DIR}/out.log
  # write results file for (10h) alexa data (add --print for pdf charts)
  # ${EXE} -c ${DIR}/candidatepairs.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --resultfile ${DIR}/results.csv > ${DIR}/write.log
  # execute alexa low runtime scans to compare with 10h runtime scans
  # ${EXE} -c ${DIR}/candidatepairs.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --low-runtime --resultfile ${DIR}/results.csv > ${DIR}/out.evaluation.log
  # do cisco candidate scans (first run)
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -sf /root/thesis/data/hostlists/resolved_cisco.csv -vv --from ${FROM} --to ${TO} --server-ports --print --resultfile > ${DIR}/out.log
  # initial low runtime measurement
  # ${EXE} -c -sf /root/thesis/data/hostlists/resolved_cisco.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --from ${FROM} --to ${TO} --low-runtime --server-ports --resultfile > ${DIR}/out.log
  # calculating results for low runtime
  # ${EXE} -c ${DIR}/candidatepairs.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -vv --low-runtime --resultfile > ${DIR}/out.evaluation.log

  # cisco port scan - interval 50k
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -sf /root/thesis/data/hostlists/resolved_cisco.csv -vv --from ${FROM} --to ${TO} --server-ports --no-evaluation > ${DIR}/out.portscan.log

  # cisco harvesting 10h 50k, candidate pairs prepared
  # ${EXE} -c ${DIR}/candidatepairs.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -vv -r --print --resultfile > ${DIR}/out.log


  # RUN SPECIFIC TASKS ON ALREADY AVAILABLE DATA - DO NOT FORGET TO ADAPT THE DIRECTORY ABOVE ACCORDINGLY
  # do nothing except loading data
  # ${EXE} -c ${DIR}/candidatepairs.csv -d ${DIR} -vv > ${DIR}/out.NOP.log
  # CANDIDATES LRT: resultfile and keyscan
  # ${EXE} -c ${DIR}/candidatepairs.csv -d ${DIR} -vv --resultfile results_${NOW}.csv --low-runtime > ${DIR}/out.tasks.${NOW}.log
  # ${EXE} -c ${DIR}/candidatepairs.csv -d ${DIR} -vv --only-ssh-keyscan --low-runtime > ${DIR}/out.tasks.${NOW}.log
  # CANDIDATES FRT: plot, resultfile and keyscan
  # ${EXE} -c ${DIR}/candidatepairs.csv -d ${DIR} -vv --print --resultfile results_${NOW}.csv > ${DIR}/out.tasks.${NOW}.log
  ${EXE} -c ${DIR}/candidatepairs.csv -d ${DIR} -vv --only-ssh-keyscan > ${DIR}/out.tasks.${NOW}.log



  let COUNTER=$TO
done

echo "$(/bin/date +"%Y-%m-%d %T") - Finished"
