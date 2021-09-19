#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
export SILENT=">/dev/null 2>&1"

function check_root() {
    real_user=$(who | awk '{print $1}')

    if [ ! $real_user = "root" ]
    then
        echo "ERROR! Must be root! Log off and re-run script as root." 
        exit 1
    fi
}

function print_header() {
    echo -e "\n### Executing function: $1 ###\n"
}

function full_update() {
    print_header ${FUNCNAME[0]}
    
    eval apt update $SILENT
    eval apt upgrade -y $SILENT
    eval apt autoremove -y $SILENT
    eval apt autoclean -y $SILENT
}

function install_basic_tools() {
    print_header ${FUNCNAME[0]}

    eval apt -y remove kali-undercover $SILENT
    eval apt -y install autogen automake build-essential cifs-utils code-oss curl dkms flameshot gcc-multilib gimp gnupg htop libffi-dev libguestfs-tools libmpc-dev libssl-dev linux-headers-amd64 manpages-dev manpages-posix-dev mlocate neovim openssl python2-dev python3.9-dev python3-argcomplete python3-dev python3-distutils python3-setuptools python3-venv python-setuptools seclists tmux wget xclip $SILENT
    full_update $SILENT
}

function revert_to_bash() {
    print_header ${FUNCNAME[0]}

    eval chsh -s /bin/bash $SILENT
    eval apt remove -y zsh $SILENT
}

function install_vm_tools() {
    print_header ${FUNCNAME[0]}

    eval apt install -y open-vm-tools open-vm-tools-desktop fuse $SILENT
    eval systemctl enable --now open-vm-tools.service $SILENT
}

function fix_power_settings() {
    print_header ${FUNCNAME[0]}

    eval wget https://raw.githubusercontent.com/Dewalt-arch/pimpmyi3-config/main/xfce4/xfce4-power-manager.xml -O /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml $SILENT
}

function fix_sources() {
    print_header ${FUNCNAME[0]}

    eval mkdir -p /etc/gcrypt
    echo "all" > /etc/gcrypt/hwf.deny

    check_space=$(cat /etc/apt/sources.list | grep -c "# deb-src http://.*/kali kali-rolling main contrib non-free")
    check_nospace=$(cat /etc/apt/sources.list | grep -c "#deb-src http://.*/kali kali-rolling main contrib non-free")
    get_current_mirror=$(cat /etc/apt/sources.list | grep "deb-src http://.*/kali kali-rolling main contrib non-free" | cut -d "/" -f3)

    if [[ $check_space = 0 && $check_nospace = 0 ]]
    then
    	echo -n ""
    elif [ $check_space = 1 ]
    then
      sed 's/\# deb-src http\:\/\/.*\/kali kali-rolling main contrib non\-free/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
    elif [ $check_nospace = 1 ]
    then
      sed 's/\#deb-src http\:\/\/.*\/kali kali-rolling main contrib non\-free/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
    fi
}

function fix_hushlogin() {
    print_header ${FUNCNAME[0]}

    if [ ! -f /root/.hushlogin ]
    then
        touch /root/.hughlogin
    fi
}

function install_pip2() {
    print_header ${FUNCNAME[0]}

    check_pip=$(whereis pip | grep -i -c "/usr/local/bin/pip2.7")
    if [ $check_pip -ne 1 ]
    then
        eval curl https://raw.githubusercontent.com/pypa/get-pip/3843bff3a0a61da5b63ea0b7d34794c5c51a2f11/2.7/get-pip.py -o /tmp/get-pip.py $SILENT
        eval python /tmp/get-pip.py $SILENT
        rm -f /tmp/get-pip.py
        eval pip --no-python-version-warning install setuptools $SILENT

        if [ ! -f /usr/bin/pip3 ]
        then
            eval apt reinstall -y python3-pip $SILENT
        fi
    fi
}

function install_pip3() {
    print_header ${FUNCNAME[0]}

    eval apt reinstall -y python3-pip $SILENT
    echo "# Python" >> /root/.bashrc
    echo -e 'export PATH=$PATH:$HOME/.local/bin\n' >> /root/.bashrc
}

function install_pipx() {
    print_header ${FUNCNAME[0]}

    eval apt install -y pipx $SILENT
    eval "$(register-python-argcomplete3 pipx)" $SILENT
    echo '# pipx' >> /root/.bashrc
    echo -e 'eval "$(register-python-argcomplete3 pipx)"\n' >> /root/.bashrc
    eval pipx install virtualenv $SILENT
}

function install_golang() {
    print_header ${FUNCNAME[0]}

    eval apt install -y golang $SILENT

    if [ ! -d /root/go ]
    then
        mkdir -p /root/go/{bin,src}
    fi

    echo "# golang" >> /root/.bashrc
    echo 'export GOPATH=$HOME/go' >> /root/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin\n' >> /root/.bashrc
}

function fix_java() {
    print_header ${FUNCNAME[0]}

    eval apt reinstall -y openjdk-11-jdk openjdk-11-jre openjdk-11-dbg openjdk-11-doc $SILENT
    echo "# Java" >> /root/.bashrc
    echo -e 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64\n' >> /root/.bashrc
    echo -e 'export PATH=$PATH:$JAVA_HOME/bin' >> /root/.bashrc
}

function fix_nmap() {
    print_header ${FUNCNAME[0]}

    rm -f /usr/share/nmap/scripts/clamav-exec.nse
    eval wget https://raw.githubusercontent.com/nmap/nmap/master/scripts/clamav-exec.nse -O /usr/share/nmap/scripts/clamav-exec.nse $SILENT
    eval wget https://raw.githubusercontent.com/onomastus/pentest-tools/master/fixed-http-shellshock.nse -O /usr/share/nmap/scripts/http-shellshock.nse $SILENT
}

function fix_rockyou() {
    print_header ${FUNCNAME[0]}

    eval gzip -dq /usr/share/wordlists/rockyou.txt.gz $SILENT
}

function silence_pcbeep() {
    print_header ${FUNCNAME[0]}

    echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
}

function fix_python_requests() {
    print_header ${FUNCNAME[0]}

    eval git clone https://github.com/psf/requests /opt/requests $SILENT
    eval pip install colorama $SILENT
    eval pip install /opt/requests $SILENT
}

function fix_set() {
    print_header ${FUNCNAME[0]}

    eval apt -y install libssl-dev set gcc-mingw-w64-x86-64-win32 $SILENT
}

function fix_pyftpdlib() {
    print_header ${FUNCNAME[0]}

    eval pip install pyftpdlib $SILENT
}

function fix_grub() {
    print_header ${FUNCNAME[0]}

    check_grub=$(cat /etc/default/grub | grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" )

    if [ $check_grub -ne 1 ]
    then
        echo -n ""
    else
        sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' -i /etc/default/grub
        update-grub
    fi
}

function fix_smbconf() {
    print_header ${FUNCNAME[0]}

    check_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol")
    check_max=$(cat /etc/samba/smb.conf | grep -c -i "client max protocol")

    if [ $check_min -ne 0 ] || [ $check_max -ne 0 ]
    then
        echo -n ""
    else
        sed 's/\[global\]/\[global\]\n   client min protocol = CORE\n   client max protocol = SMB3\n''/' -i /etc/samba/smb.conf
    fi
}

function fix_impacket_array() {
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'GetNPUsers.py'
         'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 'lookupsid.py' 'mimikatz.py'
         'mqtt_check.py' 'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py'
         'ping.py' 'psexec.py' 'raiseChild.py' 'rdp_check.py' 'registry-read.py' 'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py'
         'secretsdump.py' 'services.py' 'smbclient.py' 'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py'
         'ticketConverter.py' 'ticketer.py' 'wmiexec.py' 'wmipersist.py' 'wmiquery.py' 'addcomputer.pyc' 'atexec.pyc' 'dcomexec.pyc' 'dpapi.pyc'
         'esentutl.pyc' 'findDelegation.pyc' 'GetADUsers.pyc' 'getArch.pyc' 'GetNPUsers.pyc' 'getPac.pyc' 'getST.pyc' 'getTGT.pyc'
         'GetUserSPNs.pyc' 'goldenPac.pyc' 'karmaSMB.pyc' 'kintercept.pyc' 'lookupsid.pyc' 'mimikatz.pyc' 'mqtt_check.pyc' 'mssqlclient.pyc'
         'mssqlinstance.pyc' 'netview.pyc' 'nmapAnswerMachine.pyc' 'ntfs-read.pyc' 'ntlmrelayx.pyc' 'ping6.pyc' 'ping.pyc' 'psexec.pyc'
         'raiseChild.pyc' 'rdp_check.pyc' 'registry-read.pyc' 'reg.pyc' 'rpcdump.pyc' 'rpcmap.pyc' 'sambaPipe.pyc' 'samrdump.pyc'
         'secretsdump.pyc' 'services.pyc' 'smbclient.pyc' 'smbexec.pyc' 'smbrelayx.pyc' 'smbserver.pyc' 'sniffer.pyc' 'sniff.pyc' 'split.pyc'
         'ticketConverter.pyc' 'ticketer.pyc' 'wmiexec.pyc' 'wmipersist.pyc' 'wmiquery.pyc' )

    for impacket_file in ${arr[@]}; do
        rm -f /usr/bin/$impacket_file /usr/local/bin/$impacket_file /root/.local/bin/$impacket_file
    done
}

function fix_impacket() {
    print_header ${FUNCNAME[0]}

    eval pip uninstall impacket -y $SILENT
    eval pip3 uninstall impacket -y $SILENT
    fix_impacket_array
    eval wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_23/impacket-0.9.23.tar.gz -O /tmp/impacket-0.9.23.tar.gz $SILENT
    eval tar xfz /tmp/impacket-0.9.23.tar.gz -C /opt $SILENT
    chown -R root:root /opt/impacket-0.9.23
    chmod -R 755 /opt/impacket-0.9.23
    eval pip3 install lsassy $SILENT
    eval pip install flask $SILENT
    eval pip install pyasn1 $SILENT
    eval pip install pycryptodomex $SILENT
    eval pip install pyOpenSSL $SILENT
    eval pip install ldap3 $SILENT
    eval pip install ldapdomaindump $SILENT
    eval pip install wheel $SILENT
    eval pip install /opt/impacket-0.9.23 $SILENT
    rm -f /tmp/impacket-0.9.23.tar.gz
    eval apt -y reinstall python3-impacket impacket-scripts $SILENT
}

function apply_fixes() {
    print_header ${FUNCNAME[0]}

    revert_to_bash
    install_vm_tools
    fix_power_settings
    fix_sources
    fix_hushlogin
    install_pip2
    install_pip3
    install_pipx
    install_golang
    fix_java
    fix_nmap
    fix_rockyou
    silence_pcbeep
    fix_python_requests
    fix_set
    fix_pyftpdlib
    fix_grub
    fix_smbconf
    fix_impacket
    full_update
}

function setup_ssh_keys() {
    print_header ${FUNCNAME[0]}

    if [ ! /root/.ssh/id_ed25519 ]
    then
        HOSTNAME=`hostname` ssh-keygen -t ed25519 -C "$HOSTNAME" -f "$HOME/.ssh/id_ed25519" -P "" >/dev/null 2>&1
        eval `ssh-agent -s` $SILENT
        eval ssh-add /root/.ssh/ed_ed25519 $SILENT
    fi
}

function setup_git() {
    print_header ${FUNCNAME[0]}

    eval apt install -y git $SILENT
    eval git config --global pull.rebase true $SILENT
    eval git config --global user.name "$1" $SILENT
    eval git config --global user.email "$2" $SILENT
    eval git config --global init.defaultBranch main $SILENT
}

function setup_configs() {
    print_header ${FUNCNAME[0]}

    if [ ! -d /root/dotfiles ];
    then
        eval git clone git@github.com:xbufu/dotfiles.git /root/dotfiles $SILENT
    fi

    ln -s /root/dotfiles/bash/.bash_aliases /root/.bash_aliases

    # Set up neovim
    eval sh -c 'curl -fLo "${XDG_DATA_HOME:-$HOME/.local/share}"/nvim/site/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim' $SILENT
    mkdir -p /root/.config/nvim
    ln -s /root/dotfiles/nvim/init.vim /root/.config/nvim/init.vim
    eval nvim --headless +PlugInstall +qa $SILENT

    # Set up tmux
    ln -s /root/dotfiles/tmux/.tmux.conf /root/.tmux.conf
    mkdir -p /root/.config/tmux
    ln -s /root/dotfiles/tmux/vpn.sh /root/.config/tmux/vpn.sh
    echo -e "\nsource /root/.bashrc" >> /root/.profile
    echo -e "\nsource /root/.bashrc" >> /root/.bash_profile
}

function install_kali_tools() {
    print_header ${FUNCNAME[0]}

    eval apt install -y amass apache2 arping arp-scan binwalk bloodhound bulk-extractor burpsuite cadaver cewl chntpw commix crunch cryptcat davtest dmitry dns2tcp dnschef dnsenum dnsrecon dos2unix enum4linux exe2hexbat exiftool exploitdb feroxbuster fierce fping ffuf gdb ghex ghidra git gobuster gparted gpp-decrypt hashcat hashcat-utils hping3 hydra john laudanum macchanger maltego maltego-teeth masscan metasploit-framework mimikatz nasm nbtscan netdiscover ngrep nikto nmap onesixtyone oscanner passing-the-hash powershell-empire proxychains python3-yaml radare2 radare2-cutter rdesktop recon-ng responder samdump2 seclists set sipvicious smbclient smbmap smtp-user-enum snmp snmpcheck socat sqlitebrowser sqlmap ssldump sslscan sslsplit sslyze starkiller steghide thc-ipv6 tnscmd10g vlan webshells whatweb windows-binaries winexe wireshark wkhtmltopdf wordlists wpscan xpdf xxd $SILENT
    full_update
}

function install_enum4linux-ng() {
    print_header ${FUNCNAME[0]}

    eval apt install -y smbclient python3-ldap3 python3-yaml python3-impacket $SILENT
    eval git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng $SILENT
    eval pip3 install -r /opt/enum4linux-ng/requirements.txt $SILENT
    ln -s /opt/enum4linux-ng/enum4linux-ng.py /usr/bin/enum4linux-ng
}

function install_pwntools() {
    print_header ${FUNCNAME[0]}

    eval pip3 install pwntools $SILENT
    eval pip3 install capstone $SILENT
    eval pip3 install unicorn $SILENT
    eval pip3 install keystone-engine $SILENT
    eval pip3 install ropper $SILENT
    eval git clone https://github.com/hugsy/gef.git /opt/gef $SILENT
    echo 'source /opt/gef/gef.py' >> /root/.gdbinit
    echo 'set disassembly-flavor intel' >> /root/.gdbinit
}

function install_crypto_tools() {
    print_header ${FUNCNAME[0]}

    eval pipx install name-that-hash $SILENT
    eval pipx install search-that-hash $SILENT
    eval pipx install stegcracker $SILENT
    eval git clone https://github.com/Ganapati/RsaCtfTool /opt/RsaCtfTool $SILENT
    eval pip3 install -r /opt/RsaCtfTool/requirements.txt $SILENT
}

function setup_privesc_tools() {
    print_header ${FUNCNAME[0]}

    # Linux
    eval git clone https://github.com/andrew-d/static-binaries.git /opt/static-binaries $SILENT
    eval git clone https://github.com/rebootuser/LinEnum.git /opt/LinEnum $SILENT
    eval git clone https://github.com/mzet-/linux-exploit-suggester /opt/linux-exploit-suggester $SILENT
    eval git clone https://github.com/Anon-Exploiter/SUID3NUM /opt/SUID3NUM $SILENT
    eval git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite /opt/privilege-escalation-awesome-scripts-suite $SILENT
    eval git clone https://github.com/saghul/lxd-alpine-builder /opt/lxd-alpine-builder $SILENT
    eval git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell /opt/wwwolf-php-webshell $SILENT
    eval git clone https://github.com/ivan-sincek/php-reverse-shell /opt/php-reverse-shell $SILENT
    eval git clone https://github.com/AlmCo/Shellshocker /opt/shellshocker $SILENT
    eval pipx install git+https://github.com/ihebski/DefaultCreds-cheat-sheet.git $SILENT
    eval git clone https://github.com/cwinfosec/revshellgen /opt/revshellgen $SILENT
    chmod +x /opt/revshellgen/revshellgen.py
    ln -s /opt/revshellgen/revshellgen.py /usr/bin/rsg
    mkdir /opt/pspy
    eval wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 /opt/pspy/pspy32 $SILENT
    eval wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32s /opt/pspy/pspy32s $SILENT
    eval wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 /opt/pspy/pspy64 $SILENT
    eval wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s /opt/pspy/pspy64s $SILENT
    
    # Windows
    eval git clone https://github.com/samratashok/nishang /opt/nishang $SILENT
    eval git clone https://github.com/PowerShellMafia/PowerSploit /opt/PowerSploit $SILENT
    eval git clone https://github.com/3ndG4me/AutoBlue-MS17-010 /opt/AutoBlue-MS17-010 $SILENT
    eval git clone https://github.com/helviojunior/MS17-010 /opt/MS17-010 $SILENT
    eval git clone https://github.com/worawit/MS17-010 /opt/MS17-010-OG $SILENT
    eval git clone https://github.com/andyacer/ms08_067 /opt/ms08_067 $SILENT
    eval git clone https://github.com/ivan-sincek/powershell-reverse-tcp /opt/powershell-reverse-tcp $SILENT
    eval git clone https://github.com/turbo/zero2hero /opt/zero2hero-uac-bypass $SILENT
    eval git clone https://github.com/samratashok/ADModule /opt/ADModule $SILENT
    eval git clone https://github.com/ivan-sincek/powershell-reverse-tcp /opt/powershell-reverse-tcp $SILENT
    eval git clone https://github.com/ivan-sincek/java-reverse-tcp /opt/java-reverse-tcp $SILENT
}

function setup_pe_tools() {
    print_header ${FUNCNAME[0]}

    eval git clone https://github.com/xbufu/pe_tools /opt/pe_tools $SILENT
}

function usage() {
    echo "usage: $0 [-h] [-v] -u GIT_USERNAME -e GIT_EMAIL"
}

while getopts "u:e:hv" flag
do
    case "${flag}" in
        u) git_user=${OPTARG};;
        e) git_email={OPTARG};;
        v) export SILENT="";;
        h | *) usage; exit;;
    esac
done

if [ -z "$git_user" ] || [ -z "$git_email" ]
then
    usage
    exit 1
fi

check_root
full_update
install_basic_tools
apply_fixes
setup_ssh_keys
setup_git "$git_user" "$git_email"
setup_configs
install_kali_tools
install_enum4linux-ng
install_pwntools
install_crypto_tools
setup_privesc_tools
setup_pe_tools
