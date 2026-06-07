#!/usr/bin/env bash

usage() {
    echo "Usage: $0 -i [ip] | -f [file] [-o outdir]"
    echo "  -i  Target IP or range (e.g. 192.168.1.1 or 192.168.1.1,5-10)"
    echo "  -f  File with one IP per line"
    echo "  -o  Output directory for nmap files (default: current dir)"
    echo "  -p  Use --top-ports N instead of -p- (all ports)"
    exit 1
}

HOST=""
FILE=""
OUTDIR="."
TOPPORTS=""

while getopts "i:f:o:p:" flag; do
    case "${flag}" in
        i) HOST=${OPTARG} ;;
        f) FILE=${OPTARG} ;;
        o) OUTDIR=${OPTARG} ;;
        p) TOPPORTS=${OPTARG} ;;
        *) usage ;;
    esac
done

if [[ -n "$HOST" && -n "$FILE" ]]; then
    echo "[-] -i and -f are mutually exclusive"
    usage
fi

if [[ -z "$HOST" && -z "$FILE" ]]; then
    usage
fi

scan_host() {
    local HOST=$1
    PREFIX=$(echo $HOST | cut -d"." -f1-3)
    LAST_PART=$(echo $HOST | cut -d"." -f4)

    OCTETS=""
    for PART in $(echo $LAST_PART | tr ',' ' '); do
        if [[ $PART == *"-"* ]]; then
            OCTETS="$OCTETS $(seq $(echo $PART | cut -d'-' -f1) $(echo $PART | cut -d'-' -f2))"
        else
            OCTETS="$OCTETS $PART"
        fi
    done

    for OCTET in $OCTETS; do
        TARGET="${PREFIX}.${OCTET}"
        echo "[*] Scanning target: $TARGET"
        PORT_FLAG=$([[ -n "$TOPPORTS" ]] && echo "--top-ports $TOPPORTS" || echo "-p-")
        echo "[*] nmap -Pn --min-rate=300 ${PORT_FLAG} -v --unprivileged -oN ${OUTDIR}/nmap_allporttcp_${TARGET} $TARGET"
        nmap -Pn --min-rate=300 ${PORT_FLAG} -v --unprivileged -oN "${OUTDIR}/nmap_allporttcp_${TARGET}" $TARGET
        PORTS=$(cat "${OUTDIR}/nmap_allporttcp_${TARGET}" | grep -E ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        echo "[i] ------------- done -------------"
        echo "[*] nmap -Pn -sVC -p${PORTS} -v --unprivileged -oN ${OUTDIR}/nmap_allporttcpver_${TARGET} $TARGET"
        nmap -Pn -sVC -p${PORTS} -v --unprivileged -oN "${OUTDIR}/nmap_allporttcpver_${TARGET}" $TARGET
        echo "[i] ------------- done -------------"
    done
}

mkdir -p "$OUTDIR"

if [[ -n "$HOST" ]]; then
    scan_host "$HOST"
elif [[ -n "$FILE" ]]; then
    if [[ ! -f "$FILE" ]]; then
        echo "[-] File not found: $FILE"
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        scan_host "$line"
    done < "$FILE"
fi
