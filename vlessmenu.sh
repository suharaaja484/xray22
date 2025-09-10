#!/bin/bash

kubali="\033[38;2;0;128;0m"
GREEN="\033[0;32m"
kataa="\033[31;1m"
siani="\033[0;36m"
BOLD="\033[1m"
mwisho="\033[0m"
teal_color="\033[38;2;100;182;172m"
orange="\033[0;33m"
PURPLE='\033[0;35m'
kidude="[+]"
kubali_kidude="${kubali}${kidude}${mwisho}"
kataa_kidude="${kataa}${kidude}"

todayday=$(date +%A)
todaydate=$(date +%Y-%m-%d)
todaytime=$(date +%H:%M:%S)
colors=(
  "\033[0;31m"  # Red
  "\033[0;32m"  # Green
  "\033[0;33m"  # Yellow
  "\033[0;34m"  # Blue
  "\033[0;35m"  # Purple
  "\033[0;36m"  # Cyan
  "\033[0;91m"  # Light Red
  "\033[0;92m"  # Light Green
  "\033[0;93m"  # Light Yellow
  "\033[0;94m"  # Light Blue
  "\033[0;95m"  # Light Purple
  "\033[0;96m"  # Light Cyan
)

# Function to choose a random color
function choose_random_color() {
  local num_colors=${#colors[@]}
  local random_index=$((RANDOM % num_colors))
  echo -e "${colors[random_index]}"
}
selected_color=$(choose_random_color)
banner(){
    echo -e "${selected_color}    
╦  ╦┬  ┌─┐┌─┐┌─┐  ╔╦╗┌─┐┌┐┌┬ ┬
╚╗╔╝│  ├┤ └─┐└─┐  ║║║├┤ ││││ │
 ╚╝ ┴─┘└─┘└─┘└─┘  ╩ ╩└─┘┘└┘└─┘
 ${mwisho}
    "

}
while true; do
    banner
	echo -e "$selected_color╒════════════════════════════════════════════╕\033[0m"
	echo -e " \033[0;41;36m                   \033[1mVLESS MENU                \033[0m"
	echo -e "$elected_color╘════════════════════════════════════════════╛\033[0m"
	echo -e "$selected_color╒═════════════════════════════════════════════╕\033[0m"
	echo -e "     \033[1m[-Date-]     \033[1m[-Day-]     \033[1m[-Time-]$mwisho                   "
	echo -e "     \033[1m$orange$todaydate$mwisho   \033[1m$orange$todayday$mwisho   \033[1m$orange$todaytime$mwisho              "
	echo -e "$selected_color╘════════════════════════════════════════════╛\033[0m"
	echo -e "           [1].Add VLess Account                        "
	echo -e "           [2].Check Logged In Users                        "
	echo -e "           [3].Delete VLess Account                         "
    echo -e "           [4].Block Sites                        "
	echo -e "           [5].Renew VLess Account                         "
	echo -e "           [6].Check Configs Files                          "
	echo -e "           [7].Check Bandwidth Used By Users                         "
	echo -e "           [8].Main Menu                               "
	echo -e "$selected_color╘════════════════════════════════════════════╛\033[0m"
	read -rp "${kidude}Select Operation: " operation

	if [[ $operation == 1 ]]; then
		clear
		addvless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation ==  2 ]]; then
		clear
		checkuserloginvless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation == 3 ]]; then
		clear
		deletevless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation == 4 ]]; then
		clear
		block_site_vless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation == 5 ]]; then
		clear
		renewvless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation == 6 ]]; then
		clear
		#echo -e "${kubali_kidude}This Feature Is Not Published Yet!."
		checkconfigvless
		read -rp "[:]Press Any Key To Continue.."
		clear
		panel
	elif [[ $operation == 7 ]]; then
		clear
		checkbandwith
        read -rp "[:]Press Any Key To Continue.."
        clear
        panel
    elif [[ $operation == 8 ]]; then
        clear
        panel    
	else
		echo -e "${kataa_kidude}Invalid Input${mwisho}"	
		sleep 2
		clear
	fi
