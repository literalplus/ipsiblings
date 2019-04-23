#!/usr/bin/env bash

function at_exit {
    if [ "$?" -ne 0 ] # print usage if script quit with error code
    then
        echo "Usage: $0 <ENDVALUE> <DATA_DIR> [<EXECUTABLE_DIR> <INTERVAL>]" # alexa resolved list: 231750; cisco: 495277
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
echo "$(/bin/date +"%Y-%m-%d %T") Started"
NOW=$(/bin/date +"%Y-%m-%d_%H.%M.%S")

while [ $COUNTER -lt $1 ]
do
  let FROM=${COUNTER}
  let TO=${COUNTER}+${INTERVAL}
  # echo "$FROM - $TO - $DATADIR - $EXE - $INTERVAL"

  DIR="$DATADIR/alexa_traces_$FROM-$TO"
  # DIR="$DATADIR/cisco_traces_$FROM-$TO"
  echo "$(/bin/date +"%Y-%m-%d %T") Processing range $FROM - $TO [$DIR] ..."

  mkdir -p ${DIR}
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -sf ${EXEDIR}/alexa_resolved.csv -r -vv --from ${FROM} --to ${TO} --server-ports --lowruntime > ${DIR}/out.log
  # ${EXE} -c -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --from ${FROM} --to ${TO} --server-ports > ${DIR}/out.log
  # ${EXE} -t ${DIR}/gt_nlnog_ripe.csv -i ${EXEDIR}/ignore.txt -d ${DIR} -r -vv --resultfile ${DIR}/results.csv > ${DIR}/write.log

  # ./main.py -t -sf gt_nlnog_ripe_full_semicolon_header.csv -i ignore.txt -d /root/thesis/data/gt_nlnog_ripe_lowruntime -vv > /root/thesis/data/gt_nlnog_ripe_lowruntime/out.log

  # alexa trace command
  # ${EXE} -t -d ${DIR} -sf /root/thesis/data/hostlists/resolved/resolved_alexa.csv -i ${EXEDIR}/ignore.txt -vv --from ${FROM} --to ${TO} --cdn-file ${EXEDIR}/cdnnets.txt --low-runtime --no-evaluation --router-ports > ${DIR}/out.log

  # cisco trace command
  # ${EXE} -t -d ${DIR} -sf /root/thesis/data/hostlists/resolved/resolved_cisco.csv -i ${EXEDIR}/ignore.txt -vv --from ${FROM} --to ${TO} --cdn-file ${EXEDIR}/cdnnets.txt --low-runtime --no-evaluation --router-ports > ${DIR}/out.log


  # RUN SPECIFIC TASKS ON ALREADY AVAILABLE DATA - DO NOT FORGET TO ADAPT THE DIRECTORY ABOVE ACCORDINGLY
  # TRACES LRT: resultfile and keyscan
  # ${EXE} -ld ${DIR} -vv --resultfile results_${NOW}.csv --low-runtime > ${DIR}/out.tasks.${NOW}.log
  # TRACES LRT: only keyscan and harvesting
  ${EXE} -ld ${DIR} -vv -r --only-ssh-keyscan --low-runtime > ${DIR}/out.tasks.${NOW}.log
  # do nothing
  # ${EXE} -ld ${DIR} -vv --no-ssh-keyscan --low-runtime > ${DIR}/out.tasks.${NOW}.log

  let COUNTER=$TO
done

echo "$(/bin/date +"%Y-%m-%d %T") Finished"
