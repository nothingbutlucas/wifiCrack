#!/bin/env bash
#
# Colours and uses

export red='\033[0;31m'    # Something went wrong
export green='\033[0;32m'  # Something went well
export yellow='\033[0;33m' # Warning
export blue='\033[0;34m'   # Info
export purple='\033[0;35m' # When asking something to the user
export cyan='\033[0;36m'   # Something is happening
export grey='\033[0;37m'   # Show a command to the user
export nc='\033[0m'        # No Color
export wrong=${red}
export good=${green}
export warn=${yellow}
export info=${blue}
export ask=${purple}
export doing=${cyan}
export cmd=${grey}

# gum variables

nothing_but_lucas_green="#BFEA00"

export BORDER="rounded"
export MARGIN="1 1"
export PADDING="1 1"
export ALIGN="center"
export BOLD=1
export BORDER_FOREGROUND=$nothing_but_lucas_green
export GUM_CHOOSE_CURSOR="~> "
export GUM_CHOOSE_CURSOR_PREFIX="[ ] "
export GUM_CHOOSE_SELECTED_PREFIX="[*] "
export GUM_CHOOSE_UNSELECTED_PREFIX="[ ] "
export GUM_CHOOSE_CURSOR_FOREGROUND=$nothing_but_lucas_green
export GUM_CHOOSE_SELECTED_FOREGROUND=$nothing_but_lucas_green
export GUM_SPIN_SPINNER="pulse"
export GUM_SPIN_SPINNER_FOREGROUND=$nothing_but_lucas_green
export GUM_CONFIRM_SELECTED_BACKGROUND=$nothing_but_lucas_green
export GUM_TABLE_HEADER_FOREGROUND=$nothing_but_lucas_green
export GUM_CHOOSE_HEADER_FOREGROUND=$nothing_but_lucas_green
