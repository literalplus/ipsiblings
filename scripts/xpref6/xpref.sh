#!/usr/bin/env bash
#
# MRT file format readable with BGPDump:
# TABLE_DUMP2|1222905606|B|2001:660:a100:2::124|29608|2a02:4e8::/32|29608 3356 3257 2497 4725 6939 5413 5413|IGP|2001:660:a100:2::124|0|0|3257:4500 3257:5010 3356:2 3356:86 3356:500 3356:601 3356:666 3356:2064|AG|5413 62.72.136.129|
#
# Fetch all available IPv6 prefixes from routeviews project and ripe data archive
# Outputs 2 files:
# -) file with unique prefixes
# -) file with unique previous/next hops
#
# Test with "route-views.perth" and "rrc18" datasets


function at_exit {
    if [ "$?" -ne 0 ]
    then
        echo "Usage: $0 <DATADIRECTORY>"
        exit 1
    fi

    exit 0
}

trap at_exit EXIT # print usage if script quit with error code

set -u # Treat unset variables as an error when substituting

DATADIR=$1


NRCONCURRENT=8 # parallel operations for sort
MAINMEMSIZE=4G # main memory buffer for sort

BGPDUMP=$(which bgpdump) # https://bitbucket.org/ripencc/bgpdump/wiki/Home

SORT=$(which sort)
WGET=$(which wget)
CAT=$(which cat)
ZCAT=$(which zcat)
BZCAT=$(which bzcat)
CURL=$(which curl)
UNIQ=$(which uniq)
GREP=$(which grep)
TAIL=$(which tail)
SED=$(which sed)
AWK=$(which awk)
DATECMD=$(which date)
RM=$(which rm)
MKDIR=$(which mkdir)
MV=$(which mv)
PWD=$(which pwd)


RVIEWS="
route-views.perth
route-views.eqix
route-views.isc
route-views.kixp
route-views.jinx
route-views.linx
route-views.nwax
route-views.telxatl
route-views.wide
route-views.sydney
route-views.saopaulo
route-views.sg
route-views.sfmix
route-views.soxrs
"

RIPEHOSTS="
rrc21
rrc20
rrc19
rrc18
rrc16
rrc15
rrc14
rrc13
rrc12
rrc11
rrc10
rrc09
rrc08
rrc07
rrc06
rrc05
rrc04
rrc03
rrc02
rrc01
rrc00
"


echo "Started at $($DATECMD)"


# determine current data for RouteViews format and obtain name of latest file
DATEM=$($DATECMD +%Y.%m)
RVIEWLATEST=$($CURL http://archive.routeviews.org/route-views.nwax/bgpdata/$DATEM/RIBS/ 2> /dev/null | $GREP -o -E '>(rib[^<]+)' | $TAIL -n 1 | $SED s/.//)

# determine indexing date
#NOW=$($DATECMD +%s) # timestamp in seconds
NOW=$($DATECMD +%F_%H-%M-%S) # yyyy-mm-dd_hh-mm-ss

# Prefix used for data directory
PRFX="$DATADIR/$NOW"
LOGDIR="$PRFX/log"

# create data storage directory
$MKDIR -p $PRFX
$MKDIR -p $LOGDIR


for i in $RVIEWS
do
    FILE="$PRFX/$i.bz2"
    echo "---- CURRENT FILE: $FILE"
    #$WGET -o $PRFX/$i-gather.log -O $FILE "http://archive.routeviews.org/$i/bgpdata/$DATEM/RIBS/$RVIEWLATEST"
    #$WGET -o $PRFX/$i-gather.log -O $FILE "http://[2001:468:d01:33::80df:3314]/$i/bgpdata/$DATEM/RIBS/$RVIEWLATEST"
    $WGET -o $LOGDIR/$i-gather.log -O $FILE "http://128.223.51.20/$i/bgpdata/$DATEM/RIBS/$RVIEWLATEST"

    $BZCAT $FILE | $BGPDUMP -m -v - | $AWK -F "|" '$6 ~ /[0-9a-fA-F]+:/ { for (i=4; i<NF; i++) printf $i "|"; print $NF }' > $PRFX/$i-mrt-v6 # only IPv6 prefix lines
    # offset -3 for columns
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$3]++ { print $3 }' > $PRFX/$i-net-v6 # uniq-ing prefixes and output
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$1]++ { print $1 }' > $PRFX/$i-prev-v6 # uniq-ing previous hop and output
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$6]++ { print $6 }' > $PRFX/$i-next-v6 # uniq-ing next hop and output

    $RM $FILE
    $RM $PRFX/$i-mrt-v6
done

for i in $RIPEHOSTS
do
    FILE="$PRFX/$i.gz"
    echo "---- CURRENT FILE: $FILE"
    #$WGET -o $PRFX/$i-gather.log -O $FILE "http://data.ris.ripe.net/$i/latest-bview.gz"
    #$WGET -o $PRFX/$i-gather.log -O $FILE "http://[2001:67c:2e8:22::c100:684]/$i/latest-bview.gz"
    $WGET -o $LOGDIR/$i-gather.log -O $FILE "http://193.0.6.132/$i/latest-bview.gz"

    $ZCAT $FILE | $BGPDUMP -m -v - | $AWK -F "|" '$6 ~ /[0-9a-fA-F]+:/ { for (i=4; i<NF; i++) printf $i "|"; print $NF }' > $PRFX/$i-mrt-v6 # only IPv6 prefix lines
    # offset -3 for columns
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$3]++ { print $3 }' > $PRFX/$i-net-v6 # uniq-ing prefixes and output
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$1]++ { print $1 }' > $PRFX/$i-prev-v6 # uniq-ing previous hop and output
    $CAT $PRFX/$i-mrt-v6 | $AWK -F "|" '!a[$6]++ { print $6 }' > $PRFX/$i-next-v6 # uniq-ing next hop and output

    $RM $FILE
    $RM $PRFX/$i-mrt-v6
done


echo "uniq-ing prefixes"

$CAT $PRFX/*net-v6 | $SORT --parallel=$NRCONCURRENT -S $MAINMEMSIZE | $UNIQ >  $PRFX/prefixes-uniq-net-v6

echo "combining and uniq-ing previous/next hops"

$CAT $PRFX/*-prev-v6 $PRFX/*-next-v6 | $SORT --parallel=$NRCONCURRENT -S $MAINMEMSIZE | $UNIQ > $PRFX/hops-uniq-net-v6

echo "Finished at $($DATECMD)"

# requires output redirection of current script: > run.log
$MV $PWD/run.log $LOGDIR/
