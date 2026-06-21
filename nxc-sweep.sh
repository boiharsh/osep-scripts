#!/usr/bin/env bash

# Initialize variables
ip=""
user=""
password=""
hash=""
domain=""
KERBEROS=""
IGNORE_SERVICES=""
auth_count=0

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

discover_hosts() {
    local proto="$1"
    local port
    case "${proto}" in
        ssh) port=22 ;;
        ftp) port=21 ;;
        *) echo "[-] discover_hosts: unknown protocol '${proto}'"; return 1 ;;
    esac
    echo "[i] Discovering ${proto^^} hosts (port ${port}) in ${iprange}"
    echo "[*] rustscan -a $iprange -p ${port} --no-banner -g 2>/dev/null" >&2
    rustscan -a $iprange -p ${port} -g --no-banner 2>/dev/null | awk '{print $1}' > /tmp/rustscan
}

while getopts i:u:p:H:d:Phkx: flag
do
    case "${flag}" in
        i) ip=${OPTARG}
        ;;
        u) user=${OPTARG}
        ;;
        p) password=${OPTARG}; ((auth_count++))
        ;;
        H) hash=${OPTARG}; ((auth_count++))
        ;;
        d) domain=${OPTARG}
        ;;
        P) PROXYCHAINS="true"
        ;;
        k) KERBEROS="true"; ((auth_count++))
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

if [[ $auth_count -gt 1 ]]; then
    echo "[-] Error: -p, -H, and -k are mutually exclusive"
    usage
fi

if [[ "$PROXYCHAINS" == "true" ]]; then
    NXC="sudo proxychains4 $(which nxc)"
    HYDRA="sudo proxychains4 $(which hydra)"
else
    NXC="nxc"
    HYDRA="hydra"
fi

iprange="$(echo $ip | cut -d'.' -f1-3).0/24"

if [[ -n "$password" ]]; then
    for proto in smb mssql winrm rdp; do
        is_ignored "$proto" && continue
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -p $password --continue-on-success --local-auth"
        if [[ -n "$domain" ]]; then
            run_cmd "${NXC} $proto $iprange -u ${domain}\\${user} -p $password --continue-on-success"
        fi
    done
    for proto in ssh ftp; do
        is_ignored "$proto" && continue
        discover_hosts "${proto}"
        if [[ -f "/tmp/rustscan" ]]; then
            run_cmd "${HYDRA} -l ${user} -p ${password} -w 2 -t 32 -I -M /tmp/rustscan ${proto}"
            if [[ -n "$domain" ]]; then
                run_cmd "${HYDRA} -l ${domain}\\${user} -p ${password} -w 2 -t 32 -I -M /tmp/rustscan ${proto}"
            fi
        fi
        rm /tmp/rustscan
    done
    exit 0
fi

if [[ -n "$hash" ]]; then
    for proto in smb mssql rdp winrm; do
        is_ignored "$proto" && continue
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success"
        run_cmd "${NXC} $proto $iprange -u $user -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success --local-auth"
        if [[ -n "$domain" ]]; then
            run_cmd "${NXC} $proto $iprange -u ${domain}\\${user} -H aad3b435b51404eeaad3b435b51404ee:$hash --continue-on-success"
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