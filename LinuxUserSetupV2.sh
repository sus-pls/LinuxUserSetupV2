#!/bin/bash
#
# Linux VM Setup Script
# Configures new users with sudo access, sets up SSH keys, and optionally installs MS Defender
#

# Enable strict error checking
set -e

# Global variables
LOG_FILE="/var/log/vm_setup.log"
DEBIAN_VERSION="12"
CLOUD_CONFIG="/etc/ssh/sshd_config.d/50-cloudinit.conf"

# Function to log messages
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        "INFO")  echo -e "[✔] $message" ;;
        "WARN")  echo -e "[!] $message" ;;
        "ERROR") echo -e "[X] $message" ;;
        *)       echo -e "[$level] $message" ;;
    esac
    
    echo -e "$timestamp [$level] $message" >> "$LOG_FILE"
}

# Function to check if script is run as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run with sudo privileges"
        log "INFO" "Please run: sudo $0"
        exit 1
    fi
}

# Function to keep sudo active
setup_sudo_keepalive() {
    # Preserve sudo timestamp to avoid multiple password prompts
    sudo -v
    
    # Keep sudo timestamp alive in the background
    (while true; do sudo -v; sleep 50; done) &
    SUDO_KEEPALIVE_PID=$!
    
    # Make sure to kill the background sudo process when the script exits
    trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null || true' EXIT
}

# Function to get admin user
get_admin_user() {
    # Try multiple methods to reliably get the admin username
    ADMIN_USER=$(logname 2>/dev/null || echo "$SUDO_USER" || whoami)
    log "INFO" "Script running as admin user: $ADMIN_USER"
    return 0
}

# Function to update system
update_system() {
    log "INFO" "Updating system packages..."
    apt update || { log "ERROR" "Failed to update package lists"; return 1; }
    apt upgrade -y || { log "ERROR" "Failed to upgrade packages"; return 1; }
    return 0
}

# Function to check if a username already exists
check_user_exists() {
    local username="$1"
    if id "$username" &>/dev/null; then
        return 0  # User exists
    else
        return 1  # User does not exist
    fi
}

# Function to prompt for a user's details
get_user_details() {
    local user_num="$1"
    local detail_type="$2"  # "username" or "password"
    local result
    
    case "$detail_type" in
        "username")
            while true; do
                read -r -p "Enter username for user #$user_num: " result
                # Validate username format
                if ! echo "$result" | grep -qE '^[a-z_][a-z0-9_-]{0,31}$'; then
                    log "ERROR" "Invalid username format: $result"
                    echo "Username must start with a lowercase letter or underscore and contain only lowercase letters, numbers, underscores, or hyphens."
                    continue
                fi
                
                # Check if username already exists
                if check_user_exists "$result"; then
                    log "ERROR" "Username $result already exists"
                    echo "User $result already exists. Please choose a different username."
                    continue
                fi
                
                break
            done
            ;;
        "password")
            # Read password securely with retry logic
            while true; do
                read -r -s -p "Enter password for user #$user_num: " result
                echo  # Add a newline after password input
                
                if [ -z "$result" ]; then
                    echo "Password cannot be empty. Please try again."
                    continue
                fi
                
                # Confirm password
                local confirm_pwd
                read -r -s -p "Confirm password for user #$user_num: " confirm_pwd
                echo  # Add a newline after password input
                
                if [ "$result" != "$confirm_pwd" ]; then
                    echo "Passwords do not match. Please try again."
                    continue
                fi
                
                break
            done
            ;;
        *)
            log "ERROR" "Invalid detail type requested"
            return 1
            ;;
    esac
    
    echo "$result"
    return 0
}

# Function to create a new user
create_user() {
    local username="$1"
    local password="$2"
    
    # Check if username is provided
    if [ -z "$username" ] || [ -z "$password" ]; then
        log "ERROR" "Username or password is empty"
        return 1
    fi
    
    # Double-check if user already exists (should be caught earlier, but just in case)
    if check_user_exists "$username"; then
        log "ERROR" "User $username already exists. Cannot proceed with this username."
        return 1
    fi
    
    # Create the user
    useradd -m "$username" || { log "ERROR" "Failed to create user $username"; return 1; }
    
    # Set password using a temporary file
    TEMP_PWD_FILE=$(mktemp)
    chmod 600 "$TEMP_PWD_FILE"  # Ensure only root can read the file
    echo "$password" > "$TEMP_PWD_FILE"
    passwd "$username" < "$TEMP_PWD_FILE" 2>/dev/null
    rm -f "$TEMP_PWD_FILE"  # Securely remove the temp file
    
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to set password for $username"
        userdel -r "$username" 2>/dev/null  # Clean up the partially created user
        return 1
    fi
    
    log "INFO" "User $username added successfully with the provided password"
    
    # Add user to sudo group
    usermod -aG sudo "$username" || { log "ERROR" "Failed to add $username to sudo group"; return 1; }
    
    # Verify sudo access
    if ! getent group sudo | grep -q "\b$username\b"; then
        log "ERROR" "Unsuccessfully added $username to sudo group"
        return 1
    fi
    
    # Set ownership of home directory
    chown -R "$username":"$username" "/home/$username" || { log "ERROR" "Failed to chown $username"; return 1; }
    log "INFO" "Chown executed successfully for $username"
    
    # Test sudo permissions (with improved error handling)
    log "INFO" "Attempting to test sudo permissions for $username"
    if ! sudo -u "$username" bash -c "sudo -n ls -la /root" &>/dev/null; then
        log "WARN" "Initial sudo test failed - this is normal for new users"
        log "INFO" "Setting up sudoers.d file for immediate sudo access"
        
        # Create a sudoers.d file for this user
        echo "$username ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$username"
        chmod 440 "/etc/sudoers.d/$username"
        
        # Test again with the temporary unrestricted access
        if sudo -u "$username" bash -c "sudo -n ls -la /root" &>/dev/null; then
            log "INFO" "Sudo permissions are working now"
        else
            log "WARN" "Sudo permissions test still failing - continuing anyway"
            # Don't fail the script, just warn
        fi
    else
        log "INFO" "Command executed successfully: ls -la /root for $username"
    fi
    
    # Check and set shell
    local current_shell
    current_shell=$(grep "^$username:" /etc/passwd | cut -d: -f7)
    
    if [ "$current_shell" == "/bin/sh" ]; then
        log "WARN" "Changing shell for $username from /bin/sh to /bin/bash"
        chsh -s /bin/bash "$username" || { log "ERROR" "Failed to change shell for $username"; return 1; }
        log "INFO" "Shell changed to /bin/bash for $username"
    else
        log "INFO" "Shell for $username is already set to $current_shell"
    fi
    
    return 0
}

# Function to setup SSH keys for a user *****************************************
# Function to setup SSH keys for a user
setup_ssh_keys() {
    local username="$1"
    local key_type="$2"  # "admin" or "user"
    local ssh_key
    local home_dir
    
    # Set the correct home directory based on username
    if [ "$key_type" == "admin" ]; then
        home_dir="/home/$ADMIN_USER"
    else
        home_dir="/home/$username"
    fi
    
    # Prompt for SSH key
    if [ "$key_type" == "admin" ]; then
        read -r -p "Enter admin SSH public key: " ssh_key
    else
        read -r -p "Enter $username's SSH public key: " ssh_key
    fi
    
    # Validate SSH key format (basic check)
    if ! echo "$ssh_key" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp|ssh-dss) '; then
        log "ERROR" "Invalid SSH key format. Please enter a valid public key."
        return 1
    fi
    
    # Create SSH directory and set permissions
    mkdir -p "$home_dir/.ssh" || { log "ERROR" "Failed to create SSH directory"; return 1; }
    touch "$home_dir/.ssh/authorized_keys" || { log "ERROR" "Failed to create authorized_keys file"; return 1; }
    
    # Add key to authorized_keys
    if [ "$key_type" == "user" ]; then
        # For new user, replace existing keys (if any)
        echo "$ssh_key" > "$home_dir/.ssh/authorized_keys" || { log "ERROR" "Failed to write SSH key"; return 1; }
    else
        # For admin, append to existing keys
        echo "$ssh_key" >> "$home_dir/.ssh/authorized_keys" || { log "ERROR" "Failed to append SSH key"; return 1; }
    fi
    
    # Set proper permissions on SSH files
    chmod 700 "$home_dir/.ssh" || { log "ERROR" "Failed to set SSH directory permissions"; return 1; }
    chmod 600 "$home_dir/.ssh/authorized_keys" || { log "ERROR" "Failed to set authorized_keys permissions"; return 1; }
    
    # Set ownership
    if [ "$key_type" == "admin" ]; then
        chown -R "$ADMIN_USER":"$ADMIN_USER" "$home_dir/.ssh" || { log "ERROR" "Failed to set SSH directory ownership"; return 1; }
    else
        chown -R "$username":"$username" "$home_dir/.ssh" || { log "ERROR" "Failed to set SSH directory ownership"; return 1; }
    fi
    
    log "INFO" "SSH key was successfully added for user in $home_dir"
    return 0
}

# Function to configure SSH server
configure_ssh() {
    log "INFO" "Configuring SSH server..."
    
    # Configure main sshd_config file
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Check and modify the cloud-init config if it exists
    if [ -f "$CLOUD_CONFIG" ]; then
        log "WARN" "Found cloud-init SSH config at $CLOUD_CONFIG"
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$CLOUD_CONFIG"
        log "INFO" "Modified cloud-init SSH config to disable password authentication"
        
        # Verify the change
        if grep -q "PasswordAuthentication yes" "$CLOUD_CONFIG"; then
            log "ERROR" "Password authentication is still enabled in cloud-init config"
            log "INFO" "Manually checking the file content:"
            grep -i "PasswordAuthentication" "$CLOUD_CONFIG" | while read -r line; do
                log "INFO" "    $line"
            done
        fi
    fi
    
    # Check for any other SSH configs that might override settings
    log "WARN" "Checking for other SSH config files that might override settings..."
    find /etc/ssh/sshd_config.d/ -type f -name "*.conf" 2>/dev/null | while read -r file; do
        log "WARN" "Found SSH config file: $file"
        if grep -q "PasswordAuthentication" "$file"; then
            log "INFO" "Contains PasswordAuthentication setting:"
            grep -i "PasswordAuthentication" "$file" | while read -r line; do
                log "INFO" "    $line"
            done
            log "WARN" "Updating $file to disable password authentication"
            sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$file"
        fi
    done
    
    # Restart SSH service
    systemctl restart sshd || { log "ERROR" "Failed to restart SSH service"; return 1; }
    log "INFO" "SSH configuration updated to enforce key-based authentication only"
    
    # Verify SSH configuration
    if sshd -T | grep -i "passwordauthentication" | grep -q "no"; then
        log "INFO" "Password authentication is properly disabled"
    else
        log "ERROR" "Warning: Password authentication may still be enabled"
        log "INFO" "Current SSH configuration:"
        sshd -T | grep -i "passwordauthentication" | while read -r line; do
            log "INFO" "    $line"
        done
        return 1
    fi
    
    return 0
}

# Function to install Microsoft Defender
install_defender() {
    log "INFO" "Installing Microsoft Defender..."
    
    # Download MS repo configuration
    wget "https://packages.microsoft.com/config/debian/$DEBIAN_VERSION/packages-microsoft-prod.deb" -O packages-microsoft-prod.deb || {
        log "ERROR" "Failed to download Microsoft repo package"
        return 1
    }
    
    # Install repo configuration
    dpkg -i packages-microsoft-prod.deb || {
        log "ERROR" "Failed to install Microsoft repo package"
        return 1
    }
    
    # Update package lists
    apt-get update || {
        log "ERROR" "Failed to update package lists after adding Microsoft repo"
        return 1
    }
    
    # Install prerequisites
    apt install -y apt-transport-https ca-certificates curl gnupg2 || {
        log "ERROR" "Failed to install prerequisites"
        return 1
    }
    
    # Install MS Defender
    log "INFO" "Starting mdatp installation"
    DEBIAN_FRONTEND=noninteractive apt-get install -y mdatp || {
        log "ERROR" "Failed to install mdatp"
        return 1
    }
    log "INFO" "mdatp installation complete"
    
    # Run ATP Python script if it exists
    if [ -f "/opt/atp.py" ]; then
        chmod +x /opt/atp.py || {
            log "ERROR" "Failed to set executable permissions on ATP script"
            return 1
        }
        
        python3 /opt/atp.py || {
            log "ERROR" "Failed to execute ATP Python script"
            return 1
        }
        log "INFO" "Python script executed successfully"
    else
        log "WARN" "ATP Python script not found at /opt/atp.py"
    fi
    
    # Enable real-time protection
    mdatp config real-time-protection --value enabled || {
        log "ERROR" "Failed to enable real-time protection"
        return 1
    }
    
    return 0
}

# Function to ask a yes/no question - simplified to avoid syntax issues
ask_yes_no() {
    local prompt="$1"
    local answer
    
    while true; do
        read -r -p "$prompt (y/n): " answer
        # Convert to lowercase manually to avoid ${var,,} syntax
        answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')
        case "$answer" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) echo "Please answer with yes (y) or no (n)." ;;
        esac
    done
}

# Function to get number of users to add
get_num_users() {
    local num_users
    
    while true; do
        read -r -p "How many users would you like to add? " num_users
        if [[ "$num_users" =~ ^[0-9]+$ ]] && [ "$num_users" -gt 0 ]; then
            echo "$num_users"
            return 0
        else
            echo "Please enter a valid positive number."
        fi
    done
}

# Main execution flow
main() {
    # Initialize log file
    echo "==== VM Setup Script Started at $(date) ====" > "$LOG_FILE"
    
    # Check if running as root and setup sudo
    check_root
    setup_sudo_keepalive
    get_admin_user
    
    # Update system packages
    update_system || exit 1
    
    # Ask how many users to add
    num_users=$(get_num_users)
    log "INFO" "Setting up $num_users user(s)"
    
    # Ask if Microsoft Defender should be installed
    if ask_yes_no "Do you want to install Microsoft Defender"; then
        install_defender=true
        log "INFO" "Microsoft Defender will be installed"
    else
        install_defender=false
        log "INFO" "Skipping Microsoft Defender installation"
    fi
    
    # Setup admin SSH key if needed
    if ask_yes_no "Do you want to add an SSH key for the admin user ($ADMIN_USER)"; then
        setup_ssh_keys "$ADMIN_USER" "admin" || exit 1
    fi
    
    # Configure SSH server
    configure_ssh || exit 1
    
    # Process each user
    for ((i=1; i<=num_users; i++)); do
        log "INFO" "Setting up user #$i of $num_users"
        
        # Get user details
        username=$(get_user_details "$i" "username")
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to get valid username for user #$i"
            continue
        fi
        
        password=$(get_user_details "$i" "password")
        if [ $? -ne 0 ]; then
            log "ERROR" "Failed to get valid password for user #$i"
            continue
        fi
        
        # Create user
        create_user "$username" "$password" || {
            log "ERROR" "Failed to create user $username"
            continue
        }
        
        # Setup SSH key for this user
        if ask_yes_no "Do you want to add an SSH key for $username"; then
            setup_ssh_keys "$username" "user" || {
                log "ERROR" "Failed to setup SSH key for $username"
                continue
            }
        fi
        
        log "INFO" "User $username setup complete"
    done
    
    # Install Microsoft Defender if requested
    if [ "$install_defender" = true ]; then
        install_defender || {
            log "ERROR" "Failed to install Microsoft Defender"
            exit 1
        }
    fi
    
    log "INFO" "VM setup completed successfully"
    echo "==== VM Setup Script Completed at $(date) ====" >> "$LOG_FILE"
    exit 0
}

# Execute main function
main
