#!/bin/bash

# FORMATTING & INTRODUCTION
bold="\033[1m"
boldend="\033[0m"
echo
echo -e "${bold}Welcome to VulnScanr™ by Keith Tan!${boldend}"
echo
printf "	[?] What is your name? "; read name
echo "	[#] Welcome $name!"
echo





# STAGE 1: DEFINING & INVESTIGATING TARGET NETWORK
echo -e "${bold}STAGE 1: DEFINING & INVESTIGATING TARGET NETWORK...${boldend}"
echo


# Get from User a Network to Scan; List all Hosts in Target Network:
IP_regex="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
CIDR_regex='^([0-2]?[0-9]|3[0-2])$'

echo "	[?] State the target network you want to scan..."
while true; do #prompt user to input target's IP address, then validate it
    read -p "	[?] Enter an IP Address to scan: " IP_addr
    if [[ $IP_addr =~ $IP_regex ]]; then
        break  #exit loop if IP address is valid
    else
        echo "	[!] Invalid IP address of $IP_addr, please re-enter a valid IP address."
    fi
done

while true; do #prompt user to input target's CIDR, then validate it
    read -p "	[?] Enter the CIDR Notation: /" CIDR
    if [[ $CIDR =~ $CIDR_regex ]]; then
        break  #exit loop if CIDR notation is valid
    else
        echo "	[!] Invalid CIDR notation of $CIDR, please re-enter a valid CIDR notation."
    fi
done

echo -e "	${bold}[@] Your target network is: $IP_addr/$CIDR${boldend}; List of hosts within your target network:"

# Discover Hosts in Target Network Using 'sudo nmap -sn'
readarray -t host_array < <(sudo nmap -sn ${IP_addr}/${CIDR} | grep "report" | awk '{print $(NF)}')
for host in "${host_array[@]}"; do
	echo "		$host"
done





# STAGE 2: NMAP & MASSSCAN ON TARGET NETWORK
# Prompt User to Specify an Output Directory for Scan Results:
echo
echo
echo -e "${bold}STAGE 2: PERFORMING NMAP & MASSCAN ON TARGET NETWORK...${boldend}"
read -p "	[?] Enter an output directory to save your scan: " output_dir
echo -e "	${bold}[@] Your output directory is: $output_dir${boldend}"


# Allow User to choose 'Basic' or 'Full' Scan Mode; Perform Nmap & Masscan:
echo "	[?] Choose your preferred Scan Mode:"
echo "		(A) Basic Scan: Scan the network for TCP & UDP, including Service Version and Weak Passwords."
echo "		(B) Full Scan: Use NSE, Weak Passwords and Vulnerability Analysis."
read -r option
case $option in
	A|a) #basic scan mode using 'sudo nmap -sV' & masscan
		echo "	[#] Basic Scan mode selected. Basic-scanning the network now..."
		echo "	[#] Scanning TCP Ports: sudo nmap -sV ..."
		sudo nmap -sV "${IP_addr}/${CIDR}" -oX ${output_dir}/basic_nmap.xml -o ${output_dir}/basic_nmap.txt > /dev/null 2>&1
		echo -e "	${bold}[@] Scan results saved: ${output_dir}/basic_nmap.xml & ${output_dir}/basic_nmap.txt${boldend}"
		echo "	[#] Scanning UDP Ports: sudo masscan -pU ..."
		sudo masscan ${IP_addr}/${CIDR} -pU:0-65535 --rate=100000 -oL ${output_dir}/masscan.txt > /dev/null 2>&1
		echo -e "	${bold}[@] Scan results saved: ${output_dir}/masscan.txt"
		echo -e "	${bold}[@] Basic Scan completed.${boldend}"
		;;
	B|b) #full scan mode using 'sudo nmap -sV -sC' & masscan
		echo "	[#] Full Scan mode selected. Full-scanning the network now..."
		echo "	[#] Scanning TCP Ports: sudo nmap -p- -sV -sC ..."
		sudo nmap -sV -sC "${IP_addr}/${CIDR}" -oX ${output_dir}/full_nmap.xml -o ${output_dir}/full_nmap.txt > /dev/null 2>&1
		echo -e "	${bold}[@] Scan results saved: ${output_dir}/full_nmap.xml & ${output_dir}/full_nmap.txt${boldend}"
		echo "	[#] Scanning UDP Ports: sudo masscan -pU ..."
		sudo masscan ${IP_addr}/${CIDR} -pU:0-65535 --rate=100000 -oL ${output_dir}/masscan.txt > /dev/null 2>&1
		echo -e "	${bold}[@] Scan results saved: ${output_dir}/masscan.txt"
		echo -e "	${bold}[@] Full Scan completed.${boldend}"
		;;
	*)
		echo "	[!] Invalid input, please choose either 'A' or 'B'."
		;;
esac





# STAGE 3: FINDING WEAK PASSWORDS USED IN TARGET NETWORK (USING HYDRA BRUTEFORCING)
echo
echo
echo -e "${bold}STAGE 3: FINDING WEAK PASSWORDS USED IN TARGET NETWORK FOR LOGIN SERVICES...${boldend}"
read -p "	[?] What username do you want to target? " username


# Define Password List to Use
while true; do #prompt user to define what password list to use
    echo "	[?] What password list do you want to use on the target? (A) Use default list (B) Supply your list"
    read -r pw_option
    case $pw_option in
        A|a) #using default password list
            echo "	[#] Using default password list. Downloading password.lst file..."
            wget -q -O - "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt" | head -n 20 > "${output_dir}/password.lst"
            if [ $? -eq 0 ]; then #check if last command (to download default password file) was executed successfully
                echo -e "	${bold}[@] Default password list saved to your output directory as: ${output_dir}/password.lst${boldend}"
                break
            else
                echo "	[!] Failed to download the default password file."
            fi
            ;;
        B|b) #using user's own password list
            read -p "	[?] Using your password list. Please state its file path: " ownpwlist_path
            if [ -f "$ownpwlist_path" ]; then #check if user specified a file path
                echo "	[#] Using custom password list: $ownpwlist_path"
                break
            else
                echo "	[!] Error: File not found at $ownpwlist_path"
            fi
            ;;
        *) #error-handling for all other options (deemed invalid)
            echo "	[!] Invalid input, please choose either 'A' or 'B'."
            continue #re-prompt user to choose a valid option
            ;;
    esac
done


# Bruteforce Login Services (SSH, RDP, FTP, Telnet)
hydra_login_svcs () {
	protocol_array=("ssh" "rdp" "ftp" "telnet")

	for protocol in "${protocol_array[@]}"; do #iterate and bruteforce each protocol
		echo
		echo -e "	${bold}[#] Bruteforcing into ${protocol} protocol...${boldend}"
		
		#bruteforce protocols
		if [ $pw_option == "A" ] || [ $pw_option == "a" ]; then #if user chose to use default password list...
			if [ -f "${output_dir}/password.lst" ]; then #if default password list has been downloaded...
				for host in "${host_array[@]}"; do #hydra bruteforce into all hosts
					hydra -l $username -P "${output_dir}/password.lst" "$host" ${protocol} -o ${output_dir}/${protocol}_hydra.txt > /dev/null 2>&1
				done
			else
				echo "	[!] Error: ${output_dir}/password.lst does not exist."
			fi
		else
			if [ -f "$ownpwlist_path" ]; then #if user chose to use own password list...
				for host in "${host_array[@]}"; do #hydra bruteforce into all hosts
					hydra -l $username -P "$ownpwlist_path" "$host" ${protocol} -o ${output_dir}/${protocol}_hydra.txt > /dev/null 2>&1
				done
			else
				echo "	[!] Error: $ownpwlist_path does not exist."
			fi
		fi

		#check if logins are successful:
		if grep -iq "password:" "${output_dir}/${protocol}_hydra.txt"; then #if the hydra output file contains string 'password:'...
			pw_found=$(grep -o 'password: .*' ${output_dir}/${protocol}_hydra.txt | cut -d' ' -f2)
			echo -e "	${bold}[!] Bruteforce successful. Weak password found: $pw_found${boldend}" #echo to user in terminal
			echo "[!] Bruteforce successful. Weak password found: $pw_found" >> ${output_dir}/${protocol}_hydra.txt #add to output file
		else
			echo "	[@] Bruteforce completed. No weak passwords were detected." #echo to user in terminal
			echo "[@] Bruteforce completed. No weak passwords were detected." >> ${output_dir}/${protocol}_hydra.txt #add to output file
		fi
	done
	
	echo -e "${bold}FULL HYDRA SCAN RESULTS FOR SSH, RDP, FTP, TELNET:${boldend}" >> ${output_dir}/full_hydra.txt #make new file to store all hydra results
	for protocol in "${protocol_array[@]}"; do #save all output files into a new singular file
		cat ${output_dir}/${protocol}_hydra.txt >> ${output_dir}/full_hydra.txt
		sudo rm ${output_dir}/${protocol}_hydra.txt #delete the individual files
	done
}
hydra_login_svcs





# STAGE 4: MAPPING VULNERABILITIES WITH SEARCHSPLOIT
echo
map_vulns () { #map vulnerabilities using
	if [ $option == "B" ] || [ $option == "b" ]; then #if user chose to do full scan...
		echo -e "${bold}STAGE 4: MAPPING VULNERABILITIES WITH SEARCHSPLOIT...${boldend}"
		echo -e "${bold}POTENTIAL VULNERABILITIES:${boldend}" >> ${output_dir}/potential_vulns.txt #add title to potential vulns file
		searchsploit -u > /dev/null 2>&1 #update searchsploit offline database
		searchsploit --nmap ${output_dir}/full_nmap.xml >> ${output_dir}/potential_vulns.txt 2>&1 #checks all results in Nmap's full scan .xml output file with service version
		echo -e "	${bold}[@] Vulnerabilities mapped and saved to ${output_dir}/potential_vulns.txt${bold}" #echo to user in terminal where the results are saved
	fi
}
map_vulns





# END: ALL VulnScanr™ SCANS COMPLETED - LOGGING
workwith_results () {
	echo
	echo
	echo -e "${bold}END: ALL VulnScanr™ SCANS COMPLETED.${boldend}"
	while true; do
		echo "	[?] What would you like to do?:"
		echo "		(A) Display full scan results."
		echo "		(B) Search within scan results."
		echo "		(C) Save results into a ZIP File."
		echo "		(D) Exit VulnScanr™"
		read -r results_option
		case $results_option in
			A|a) #display full scan results
				echo
				echo "	[#] Displaying full scan results:"
				cd $output_dir
				echo -e "${bold}NMAP & MASSCAN RESULTS:${boldend}"
				cat *nmap.txt
				cat masscan.txt
				cat full_hydra.txt
				if [ $option == "B" ] || [ $option == "b" ]; then
					cat potential_vulns.txt
				fi
				echo -e "	${bold}[@] Full scan results displayed.${boldend}"
				echo
				;;
			B|b) #search string in scan results
				echo
				read -p "	[?] Searching within scan results. Please specify your search string: " search_str
				echo "	[#] Search Results:"
				cd $output_dir
				cat * | grep -i "$search_str"
				echo -e "	${bold}[@] Search for "$search_str" is completed.${boldend}"
				echo
				;;
			C|c) #save scan results into ZIP file
				echo
				read -p "	[?] Saving scan results into ZIP File. Please specify your desired file name (without file extension): " zip_filename
				sudo cp -r $output_dir /home/kali/${zip_filename}
				sudo zip -j -r /home/kali/${zip_filename}.zip /home/kali/${zip_filename}
				echo -e "	${bold}[@] Scan results are zipped into new file at: /home/kali/${zip_filename}.zip"
				echo
				;;
			D|d) #exit script
				echo "	[#] Exiting VulnScanr™..."
				exit
				;;
			*) #error-handling
				echo "	[!] Invalid input, please choose either 'A', 'B', 'C' or 'D'."
				echo
				continue
				;;
		esac
	done
}
workwith_results
