#!/usr/bin/env bash

HOSTS_FILE="/etc/hosts"

while getopts "i:h" opt; do
  case $opt in
    i) TARGET_IP="$OPTARG"
    ;;
    h) echo "Usage: $0 [-i <ip_range>]"
       exit 0
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    exit 1
    ;;
  esac
done

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 [-i <ip_range>]"
    exit 1
fi

TARGET_IP="${TARGET_IP}/24"

function update_hosts() {
    IP=$1
    DOMAIN=$2

    num=0

    while IFS= read -r line; do
        num=$((num+1))
        shopt -s nocasematch
        if [[ " ${line} " =~ " ${DOMAIN} " ]]; then
            OLD_IP=$(echo $line | cut -d' ' -f1)
            echo "[+] Updating ${OLD_IP} to ${IP} for domain: ${DOMAIN}"
            echo "[*] sed -i \"${num}s|${OLD_IP}|${IP}|\" $HOSTS_FILE"
            sudo sed -i "${num}s|${OLD_IP}|${IP}|" $HOSTS_FILE
            return 0
        fi
        shopt -u nocasematch
    done < $HOSTS_FILE

    echo "[+] Adding ${IP} for domain: '$DOMAIN'"
    if [ -s "$HOSTS_FILE" ] && [ "$(tail -c 1 "$HOSTS_FILE")" != "" ]; then
        echo "" | sudo tee -a "$HOSTS_FILE"
    fi
    echo "$IP $DOMAIN" | sudo tee -a $HOSTS_FILE

    return 0
}

AWK_NAME_DOMAIN='{
    name=""; domain="";
    for (i=1; i<=NF; i++) {
        if ($i ~ /^\(name:/) { split($i,n,"[:)]"); name=tolower(n[2]) }
        else if ($i ~ /^\(domain:/) { split($i,d,"[:)]"); domain=d[2] }
    }
    if (name != "" && domain != "") print $2" "name"."domain
}'

echo "[i] Gathering hosts using smb."
nxc smb "$TARGET_IP" | grep -i smb | awk "$AWK_NAME_DOMAIN" > /tmp/output.txt
echo "[+] Done"
echo "[i] Gathering hosts using winrm."
nxc winrm "$TARGET_IP" | grep -i winrm | awk "$AWK_NAME_DOMAIN" >> /tmp/output.txt
echo "[+] Done"

echo "[i] Writing hosts to /etc/hosts file."
cat /tmp/output.txt | sort -u > /tmp/fin.txt

while IFS= read -r line; do
    IP=$(echo $line | cut -d' ' -f1)
    DOMAIN=$(echo $line | cut -d' ' -f2)
    update_hosts $IP $DOMAIN
done < /tmp/fin.txt
echo "[+] Done"

rm /tmp/output.txt /tmp/fin.txt