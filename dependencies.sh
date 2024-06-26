#!/bin/env bash

source "./config.sh"

function check_installer_manager() {
	confirmation="y"
	managers=(apt-get apt yum dnf zypper pacman emerge urpmi flatpak snap snapd pkg)
	available_managers=()
	for manager in "${managers[@]}"; do
		if command -v "$manager" &>/dev/null; then
			available_managers+=("$manager")
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

function install_hcxdumptool() {
	echo -e "${doing}[~]${nc} Installing hcxdumptool..."
	sleep 0.5
	if [[ $package_manager == "apt" ]]; then
		apt install -y libcurl4-openssl-dev libssl-dev pkg-config &>/dev/null
	fi
	git clone https://github.com/ZerBea/hcxdumptool.git &>/dev/null
	cd hcxdumptool || return
	make 1>/dev/null
	make install 1>/dev/null
	cd ..
	rm -rf hcxdumptool &>/dev/null
	if command -v hcxdumptool &>/dev/null; then
		installed_programs+=("$program")
	fi
}

function install_all_missing_dependencies() {
	$package_manager &>/dev/null
	for program in "${missing_dependencies[@]}"; do
		if [[ $program == "hcxdumptool" ]] && [[ $package_manager != "pacman" ]]; then
			install_hcxdumptool
		elif [[ $program == "hcxdumptool" ]] && [[ $package_manager == "pacman" ]]; then
			$package_manager install -Sy "$program" &>/dev/null
		fi
		if [ "$(echo $?)" == "0" ]; then
			echo -e "\n${doing}[~]${nc} Installing $program with $package_manager"
			sleep 0.2
			echo -e "${cmd}$ sudo $package_manager install $program${nc}"
			sudo "$package_manager" install "$program" -"${confirmation}" 1>/dev/null
			if [ "$(echo $?)" == "0" ]; then
				echo -e "${good}[+]${nc} $program has been installed"
				installed_programs+=("$program")
			else
				echo -e "${wrong}[-]${nc} $program could not be installed with $installer. Please, install it manually"
			fi
		else
			echo -e "${wrong}[-]${nc} Could not install $program because I could not find a package manager on your system. Please, install it manually"
		fi
	done
}

function see_all_dependencies() {
	echo -e "${info}[~]${nc} For handshakes attack:"
	echo -e "\t${info}[~]${nc} aircrack-ng -> For listing the networks and capturing the handshake"
	echo -e "\t${info}[~]${nc} tshark -> For reading the handshake file and verify it"
	echo -e "${info}[~]${nc} For PMKID attack:"
	echo -e "\t${info}[~]${nc} hcxdumptool -> For capturing the PMKID"
	echo -e "\t${info}[~]${nc} hashcat -> For cracking the PMKID"
	echo -e "${info}[~]${nc} For all the attacks"
	echo -e "\t${info}[~]${nc} macchanger -> For changing your MAC address and annonymize yourself"
	echo -e "\t${info}[~]${nc} gum -> For better UI"
	exit_script
}

function dependencies() {
	programs=(aircrack-ng macchanger hcxdumptool hashcat tshark gum)
	installed_programs=()
	missing_dependencies=()

	for program in "${programs[@]}"; do
		if ! command -v "$program" &>/dev/null; then
			echo -e "${yellow}[*] ${nc}$program could not be found"
			missing_dependencies+=("$program")
		else
			installed_programs+=("$program")
		fi
	done

	if [ ${#missing_dependencies} -gt 0 ]; then
		echo -e "\n${blue}[·]${nc} My recommendation is to install them but by yourself"
		gum confirm "Do you want to install the missing dependencies?" && check_installer_manager && install_all_missing_dependencies || echo -e "${green}[+]${nc} Ok, I will not install the missing dependencies\n" && exit_script
	fi
	programs=(aircrack-ng macchanger hcxdumptool hashcat tshark)
	if [ ${#installed_programs} -eq ${#programs} ]; then
		gum style "All dependencies are installed"
	else
		echo -e "\n${warn}[*]${nc} Some dependencies are not installed"
		for dependency in "${missing_dependencies[@]}"; do
			echo -e "${warn}[*]${nc} $dependency is not installed"
		done
		echo -e "${info}[~]${nc} Please, install them manually and run the script again"
		see_all_dependencies
		exit_script
	fi
}
