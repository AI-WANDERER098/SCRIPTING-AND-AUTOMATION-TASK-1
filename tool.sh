#!/bin/bash

# ==============================================================================
# Script Name : auth_analyzer.sh
# Objective   : Analyze Linux authentication logs to detect suspicious behavior,
#               brute-force attempts, and offending IP addresses (Lightweight UEBA).
# Author      : ABDUL RAHMAN BIN ABDULLAH AL MUSQATY
# Requirement : Functional, Error Handling, Parameterized, Formatted Output.
# ==============================================================================

# --- Global Variables & Default Settings ---
LOG_FILE="/var/log/auth.log" # Default log path for Debian/Ubuntu systems
THRESHOLD=5                  # Default failed attempt threshold for flagging
VERBOSE=0                    # Verbosity flag (0 = off, 1 = on)

# --- Color Definitions for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color / Reset

# ==============================================================================
# Function: display_help
# Purpose : Print usage instructions and flag descriptions.
# ==============================================================================
display_help() {
    echo -e "${CYAN}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo "A lightweight Bash authentication log analyzer for detecting brute-force activity."
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -f, --file PATH       Specify target log file (Default: /var/log/auth.log)"
    echo "  -t, --threshold NUM   Set failed login threshold for alerts (Default: 5)"
    echo "  -v, --verbose         Enable detailed output processing logs"
    echo "  -h, --help            Display this help menu and exit"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -f /var/log/auth.log -t 10"
    echo "  $0 --file ./custom_auth.log --verbose"
    echo ""
    exit 0
}

# ==============================================================================
# Function: parse_arguments
# Purpose : Process command-line flags passed by the user.
# ==============================================================================
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--file)
                if [[ -n "$2" && "$2" != -* ]]; then
                    LOG_FILE="$2"
                    shift 2
                else
                    echo -e "${RED}[!] Error: Option $1 requires a non-empty file path argument.${NC}" >&2
                    exit 1
                fi
                ;;
            -t|--threshold)
                if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                    THRESHOLD="$2"
                    shift 2
                else
                    echo -e "${RED}[!] Error: Option $1 requires a positive integer argument.${NC}" >&2
                    exit 1
                fi
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                display_help
                ;;
            *)
                echo -e "${RED}[!] Error: Invalid option '$1'. Use -h or --help for usage details.${NC}" >&2
                exit 1
                ;;
        esac
    done
}

# ==============================================================================
# Function: validate_environment
# Purpose : Perform pre-execution checks (file existence, readability, size).
# ==============================================================================
validate_environment() {
    # Check if file exists
    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "${RED}[!] Error: Specified log file '$LOG_FILE' does not exist.${NC}" >&2
        echo -e "${YELLOW}[*] Tip: Check the path or test with sample log data.${NC}"
        exit 1
    fi

    # Check if file is readable
    if [[ ! -r "$LOG_FILE" ]]; then
        echo -e "${RED}[!] Error: Cannot read '$LOG_FILE'. Permission denied.${NC}" >&2
        echo -e "${YELLOW}[*] Tip: Try running with 'sudo' if reading system auth logs.${NC}"
        exit 1
    fi

    # Check if file is non-empty
    if [[ ! -s "$LOG_FILE" ]]; then
        echo -e "${YELLOW}[!] Warning: Specified log file '$LOG_FILE' is empty. Nothing to analyze.${NC}"
        exit 0
    fi
}

# ==============================================================================
# Function: analyze_failed_logins
# Purpose : Extract and count failed login attempts grouped by source IP address.
# ==============================================================================
analyze_failed_logins() {
    echo -e "${BLUE}[+] Analyzing failed login attempts by Source IP...${NC}"

    # Extract IPs associated with failed passwords, sort, count occurrences
    local failed_ips
    failed_ips=$(grep -i "Failed password" "$LOG_FILE" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr)

    if [[ -z "$failed_ips" ]]; then
        echo -e "    ${GREEN}No failed login attempts detected.${NC}"
        return
    fi

    printf "  %-10s | %-18s | %-12s\n" "Count" "Source IP" "Status"
    echo "  --------------------------------------------------"

    while read -r count ip; do
        if [[ "$count" -ge "$THRESHOLD" ]]; then
            printf "  %-10s | %-18s | ${RED}%-12s${NC}\n" "$count" "$ip" "[ALERT - HIGH]"
        else
            printf "  %-10s | %-18s | ${GREEN}%-12s${NC}\n" "$count" "$ip" "[NORMAL]"
        fi
    done <<< "$failed_ips"
}

# ==============================================================================
# Function: analyze_targeted_users
# Purpose : Identify which user accounts (valid and invalid) are targeted most.
# ==============================================================================
analyze_targeted_users() {
    echo -e "\n${BLUE}[+] Top Targeted User Accounts (Top 5)...${NC}"

    local top_users
    # Extract user names following "for " or "for invalid user "
    top_users=$(grep -i "Failed password" "$LOG_FILE" | awk '{
        for (i=1; i<=NF; i++) {
            if ($i == "for") {
                if ($(i+1) == "invalid") {
                    print $(i+2) " (invalid)"
                } else {
                    print $(i+1)
                }
            }
        }
    }' | sort | uniq -c | sort -nr | head -n 5)

    if [[ -z "$top_users" ]]; then
        echo -e "    ${GREEN}No targeted accounts extracted.${NC}"
        return
    fi

    printf "  %-10s | %-25s\n" "Attempts" "Username / Status"
    echo "  --------------------------------------------------"
    
    while read -r count user; do
        printf "  %-10s | %-25s\n" "$count" "$user"
    done <<< "$top_users"
}

# ==============================================================================
# Function: generate_summary
# Purpose : Display summary statistics and executive analysis.
# ==============================================================================
generate_summary() {
    local total_failed
    local total_accepted

    total_failed=$(grep -i -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
    total_accepted=$(grep -i -c "Accepted password" "$LOG_FILE" 2>/dev/null || echo 0)

    echo -e "\n${CYAN}====================================================${NC}"
    echo -e "${CYAN}               EXECUTIVE LOG SUMMARY                ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e " Target Log File       : $LOG_FILE"
    echo -e " Alert Threshold       : $THRESHOLD attempts"
    echo -e " Total Failed Logins   : ${RED}$total_failed${NC}"
    echo -e " Total Successful Logins: ${GREEN}$total_accepted${NC}"
    echo -e "${CYAN}====================================================${NC}\n"
}

# ==============================================================================
# Main Execution Flow
# ==============================================================================
main() {
    parse_arguments "$@"
    validate_environment

    if [[ "$VERBOSE" -eq 1 ]]; then
        echo -e "${YELLOW}[*] Verbose mode enabled. Inspecting: $LOG_FILE${NC}"
    fi

    generate_summary
    analyze_failed_logins
    analyze_targeted_users

    echo -e "${GREEN}[✔] Log analysis complete.${NC}"
}

# Run the script with all passed command-line arguments
main "$@"
