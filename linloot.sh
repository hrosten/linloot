#!/bin/bash

################################################################################

setenv () {
    MY_NAME=$(basename $0)
    MY_VERSION="0.01"
    WHO=$(whoami)
    RESULTDIR="./linloot_$WHO"
    #if [ $DEEP -eq 1 ]; then
    #    RESULTDIR=$RESULTDIR"_deep"
    #fi
    ALLFILES="$RESULTDIR/dirlisting_$WHO.txt"
    LONGLINE=$(printf '%*s' "80" | tr ' ' "#")
    SHORTLINE=$(printf '%*s' "60" | tr ' ' "#")
    PRINTCMD=0
}

################################################################################

print_header () {
    echo
    echo $LONGLINE
    #echo " $MY_NAME $MY_VERSION (deepscan=$DEEP)"
    echo " $MY_NAME $MY_VERSION"
    echo $LONGLINE
}

################################################################################

run_command() {
    if [ "$#" -lt 3 ]; then
        echo "Error in run_command: missing parameters"
        exit 1
    fi
    local cmd="$1"
    local desc="$2"
    local out="$3"
    # Read 'silent_fail' from $4. Default to "loudfail" if not specified. 
    # Any other value will make the script hide all output from failing 
    # commands - e.g. "silentfail"
    local silent_fail=${4:-loudfail}

    cmd_out=$(eval $cmd)  
    #status=$?

    if [ ! "$cmd_out" ]; then
        if [ "$silent_fail" == "loudfail" ]; then
            echo>>$out
            echo $SHORTLINE>>$out
            echo -e "# Warning: command returned nothing:\n(cmd: $cmd)">>$out
            echo $SHORTLINE>>$out
        fi
    else
        echo>>$out
        echo $SHORTLINE>>$out
        if [ $PRINTCMD -eq 1 ]; then
            echo -e "# $desc:\n# (cmd: $cmd)">>$out
        else
            echo -e "# $desc:">>$out
        fi
        echo $SHORTLINE>>$out
        echo -e "$cmd_out">>$out
    fi
}

################################################################################

generate_allfileslist () {
    echo [+] Generating a list of all \(accessible\) files on the system
    if [ -f $ALLFILES ]; then
        echo [+] Note: using existing file listing: $ALLFILES
    else
        find / -type f >$ALLFILES 2>/dev/null
        echo [+] Wrote: $ALLFILES
    fi
}

################################################################################

check_sysinfo () {
    local out="$RESULTDIR/systeminfo_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Getting system information | tee -a $out
    echo $LONGLINE>>$out

    local cmd='cat /proc/version 2>/dev/null'
    local desc="Kernel information"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/*-release 2>/dev/null'
    local desc="Release information"
    run_command "$cmd" "$desc" "$out"

    local cmd='hostname 2>/dev/null'
    local desc="Hostname"
    run_command "$cmd" "$desc" "$out"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_userinfo () {
    local out="$RESULTDIR/userinfo_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Getting user and environmental information | tee -a $out
    echo $LONGLINE>>$out

    local cmd='whoami 2>/dev/null'
    local desc="Current user"
    run_command "$cmd" "$desc" "$out"

    local cmd='id'
    local desc="Current user id"
    run_command "$cmd" "$desc" "$out"

    local cmd='lastlog |grep -v "Never" 2>/dev/null'
    local desc="Previously logged-in users"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/passwd'
    local desc="All users"
    run_command "$cmd" "$desc" "$out"

    local cmd='grep -v '"'^[^:]*:[x]'"' /etc/passwd 2>/dev/null'
    local desc="Password hashes in /etc/passwd"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep -v "^#" /etc/passwd | awk -F: "\$3 == 0 || \$3 == 500 || \$3 == 501 || \$3 == 502 || \$3 == 1000 || \$3 == 1001 || \$3 == 1002 || \$3 == 2000 || \$3 == 2001 || \$3 == 2002 { print }"'
    local desc="Interesting users"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/shadow 2>/dev/null'
    local desc="VULNERABLE: We can read the shadow file"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/master.passwd 2>/dev/null'
    local desc="VULNERABLE: We can read the master.passwd file"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep -v -E "^#" /etc/passwd | awk -F: "\$3 == 0{print \$1}"'
    local desc="Super user account"
    run_command "$cmd" "$desc" "$out" 

    local cmd='cat /etc/sudoers 2>/dev/null |grep -v -e "^$" |grep -v "#"'
    local desc="Sudoers (condensed)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='echo '' | sudo -S -l 2>/dev/null'
    #local cmd='sudo -S -l 2>/dev/null'
    local desc="VULNERABLE: We can sudo without a password"
    run_command "$cmd" "$desc" "$out"

    local cmd='echo '' | sudo -S -l 2>/dev/null | grep -w "nmap\|perl\|"awk"\|"find"\|"bash"\|"sh"\|"man"\|"more"\|"less"\|"vi"\|"vim"\|"nc"\|"netcat"\|python\|ruby\|lua\|irb" | xargs -r ls -la 2>/dev/null'
    local desc="VULNERABLE: Possible sudo PWNAGE"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='w 2>/dev/null'
    local desc="Logged in user activity"
    run_command "$cmd" "$desc" "$out"

    local cmd='echo $PATH 2>/dev/null'
    local desc="Path information"
    run_command "$cmd" "$desc" "$out"

    local cmd='env 2>/dev/null | grep -v "LS_COLORS"'
    local desc="Environment"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/shells 2>/dev/null'
    local desc="Available shells"
    run_command "$cmd" "$desc" "$out"

    local cmd='umask -S 2>/dev/null & umask 2>/dev/null'
    local desc="Current umask value"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/login.defs 2>/dev/null |grep -i UMASK 2>/dev/null |grep -v "#" 2>/dev/null'
    local desc="umask value as specified in /etc/login.defs"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/login.defs 2>/dev/null | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE\|ENCRYPT_METHOD" 2>/dev/null | grep -v "#" 2>/dev/null'
    local desc="Password and storage information"
    run_command "$cmd" "$desc" "$out"

    local cmd='grep -i "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk "{print \$2}"'
    local desc="Root is allowed to login via SSH"
    run_command "$cmd" "$desc" "$out" "silentfail"

    #if [ $DEEP -eq 1 ]; then
    local cmd='find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -al {} \; 2>/dev/null'
    local desc="Files not owned by user but writable by group"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null'
    local desc="World-readable within /home"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -ahl ~ 2>/dev/null'
    local desc="Home directory contents"
    run_command "$cmd" "$desc" "$out" "silentfail"
    #fi

    echo [+] Wrote output to: $out
    echo
}


################################################################################

check_cron() {
    local out="$RESULTDIR/cron_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Getting cron job information | tee -a $out
    echo $LONGLINE>>$out

    local cmd='ls -la /etc/cron* 2>/dev/null'
    local desc="Scheduled cron jobs overview"
    run_command "$cmd" "$desc" "$out"

    local cmd='find /etc/cron* -perm -0002 -exec ls -la {} \; -exec cat {} 2>/dev/null \;'
    local desc="VULNERABLE: World-writable cron jobs and file contents"
    run_command "$cmd" "$desc" "$out" "siletfail"

    local cmd='cat /etc/crontab 2>/dev/null'
    local desc="Crontab contents"
    run_command "$cmd" "$desc" "$out"

    local cmd='ls -la /var/spool/cron/crontabs 2>/dev/null'
    local desc="Anything interesting in /var/spool/cron/crontabs"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null'
    local desc="Anacron jobs and associated file permissions"
    run_command "$cmd" "$desc" "$out"

    local cmd='ls -la /var/spool/anacron 2>/dev/null'
    local desc="When were jobs last executed"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null'
    local desc="Crontab jobs for all users"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /var/log -type f -iname "*cron*" -exec cat {} \;'
    local desc="Cron log files: /var/log/*cron*"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep -i CRON /var/log/syslog 2>/dev/null'
    local desc="Cron log entries in syslog"
    run_command "$cmd" "$desc" "$out" "silentfail"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_networkinfo () {
    local out="$RESULTDIR/networkinfo_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Getting networking information | tee -a $out
    echo $LONGLINE>>$out

    local cmd='/sbin/ifconfig -a 2>/dev/null'
    local desc="Networking & IP info"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/resolv.conf 2>/dev/null | grep -i "nameserver"'
    local desc="Nameserver(s)"
    run_command "$cmd" "$desc" "$out"

    local cmd='route 2>/dev/null'
    local desc="Route"
    run_command "$cmd" "$desc" "$out"

    local cmd='netstat -antp 2>/dev/null'
    local desc="Listening TCP"
    run_command "$cmd" "$desc" "$out"

    local cmd='netstat -anup 2>/dev/null'
    local desc="Listening UDP"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /proc/net/arp 2>/dev/null'
    local desc="ARP table"
    run_command "$cmd" "$desc" "$out"

    local cmd='iptables -L 2>/dev/null'
    local desc="List iptables rules"
    run_command "$cmd" "$desc" "$out" "silentfail"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_processes () {
    local out="$RESULTDIR/processinfo_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Enumerating processes and services | tee -a $out
    echo $LONGLINE>>$out

    local cmd='ps aux 2>/dev/null | awk "{print \$1,\$2,\$9,\$10,\$11}"'
    local desc="Running processes"
    run_command "$cmd" "$desc" "$out"

    local cmd='ps aux | awk "{print \$11}"|xargs -r ls -la 2>/dev/null |awk "!x[\$0]++"'
    local desc="Process binaries and permissions"
    run_command "$cmd" "$desc" "$out"

    local cmd='cat /etc/inetd.conf 2>/dev/null'
    local desc="Contents of /etc/inetd.conf"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/inetd.conf 2>/dev/null | awk "{print \$7}" |xargs -r ls -laL 2>/dev/null'
    local desc="Related inetd binary permissions"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/xinetd.conf 2>/dev/null'
    local desc="Contents of /etc/xinetd.conf"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/xinetd.conf 2>/dev/null | awk "{print \$7}" |xargs -r ls -la 2>/dev/null'
    local desc="Related xinetd binary permissions"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null'
    local desc="/etc/xinetd.d is included in /etc/xinetd.conf"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -laL /etc/xinetd.d 2>/dev/null'
    local desc="xinetd.d binary permissions"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -la /etc/init.d 2>/dev/null'
    local desc="/etc/initd.d binary permissions"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null'
    local desc="/etc/init.d/ files not belonging to root (uid 0)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -la /etc/rc.d/init.d 2>/dev/null'
    local desc="/etc/rc.d/init.d binary permissions"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /etc/rc.d/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null'
    local desc="/etc/rc.d/init.d files not belonging to root (uid 0)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -la /usr/local/etc/rc.d 2>/dev/null'
    local desc="/usr/local/etc/rc.d binary permissons"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null'
    local desc="/usr/local/etc/rc.d files not belonging to root (uid 0)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_programs () {
    local out="$RESULTDIR/programs_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Enumerating installed programs | tee -a $out
    echo $LONGLINE>>$out

    local cmd='which awk perl python ruby java gcc cc vi vim nmap find grep netcat nc ncat wget tftp ftp curl sed awk 2>/dev/null'
    local desc="Installed tools"
    run_command "$cmd" "$desc" "$out"

    local cmd='sudo -V 2>/dev/null| grep -i "Sudo version" 2>/dev/null'
    local desc="Sudo version\n (Try: http://www.exploit-db.com/search)"
    run_command "$cmd" "$desc" "$out"

    local cmd='mysql --version 2>/dev/null'
    local desc="MySQL version"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='mysqladmin -uroot -proot version 2>/dev/null'
    local desc="VULNERABLE: Connect MySQL with default root/root credentials"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='mysqladmin -uroot version 2>/dev/null'
    local desc="Connect MySQL as 'root' without password"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='psql -V 2>/dev/null'
    local desc="Postgres version"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='psql -U postgres template0 -c "select version()" 2>/dev/null | grep -i version'
    local desc="VULNERABLE: Connect Postgres DB 'template0' as user postgres with no password"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='psql -U postgres template1 -c "select version()" 2>/dev/null | grep -i version'
    local desc="VULNERABLE: Connect Postgres DB 'template1' as user postgres with no password"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='psql -U pgsql template0 -c "select version()" 2>/dev/null | grep -i version'
    local desc="VULNERABLE: Connect Postgres DB 'template0' as user psql with no password"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='psql -U pgsql template1 -c "select version()" 2>/dev/null | grep -i version'
    local desc="VULNERABLE: Connect Postgres DB 'template1' as user psql with no password"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='apache2 -v 2>/dev/null; httpd -v 2>/dev/null'
    local desc="Apache version"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='apache2ctl -M 2>/dev/null; apachectl -l 2>/dev/null'
    local desc="Apache modules"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/apache2/apache2.conf 2>/dev/null'
    local desc="Apache configuration file"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/apache2/envvars 2>/dev/null |grep -i "user\|group" |awk "{sub(/.*\export /,\"\")}1"'
    local desc="Apache user"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='dpkg -l 2>/dev/null'
    local desc="Installed packages (debian - dpkg)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='rpm -qa 2>/dev/null'
    local desc="Installed packages (Red Hat - rpm)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_filesystem () {
    local out="$RESULTDIR/filesysteminfo_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Getting filesystem information | tee -a $out
    echo $LONGLINE>>$out

    local cmd='mount'
    local desc="Mount results"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='cat /etc/fstab 2>/dev/null'
    local desc="fstab entries"
    run_command "$cmd" "$desc" "$out" "silentfail"

    echo [+] Wrote output to: $out
    echo
}

################################################################################

check_interesting_files () {
    local out="$RESULTDIR/interesting_files_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Enumerating file and directory permissions etc.| tee -a $out
    echo $LONGLINE>>$out

    local cmd='ls -ahl /root/ 2>/dev/null'
    local desc="VULNERABLE: We can read root's home directory"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='ls -ahl /home/ 2>/dev/null'
    local desc="Home directory permissions"
    run_command "$cmd" "$desc" "$out" "silentail"

    local cmd='ls -la /etc/passwd 2>/dev/null; ls -la /etc/group 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null;'
    local desc="Sensitive files"
    run_command "$cmd" "$desc" "$out" 

    local cmd='find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null | awk "{print \$1,\$3,\$4,\$5,\$6,\$7,\$8,\$9}" | tee .suidfiles.tmp'
    local desc="SUID files"
    run_command "$cmd" "$desc" "$out" 

    local cmd='grep -w "nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|pl" .suidfiles.tmp'
    local desc="Possibly interesting SUID files"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep "...s....w." .suidfiles.tmp'
    local desc="World-writable SUID files"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep "...s....w.[[:space:]]root" .suidfiles.tmp'
    local desc="VULNERABLE: World-writable SUID files owned by root"
    run_command "$cmd" "$desc" "$out" "silentfail"
####
    local cmd='find / -perm -2000 -type f -exec ls -ld {} \; 2>/dev/null | awk "{print \$1,\$3,\$4,\$5,\$6,\$7,\$8,\$9}" | tee .guidfiles.tmp'
    local desc="GUID files"
    run_command "$cmd" "$desc" "$out" 

    local cmd='grep -w "nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|pl" .guidfiles.tmp'
    local desc="Possibly interesting GUID files"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep "......s.w." .guidfiles.tmp'
    local desc="World-writable GUID files"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='grep "......s.w.[[:space:]]root" .guidfiles.tmp'
    local desc="VULNERABLE: World-writable GUID files owned by root"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find / ! -path "*/proc/*" -perm -2 -type f -exec ls -l {} \; 2>/dev/null'
    local desc="World-writable files (excluding /proc)"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;'
    local desc="Plan file permissions and contents"
    run_command "$cmd" "$desc" "$out" "silentfail"

    local cmd='find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;'
    local desc="Plan file permissions and contents"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;'
    local desc="rhost config file(s) and file contents"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;'
    local desc="rhost config file(s) and file contents"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;'
    local desc="hosts.equiv file details and contents"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null'
    local desc="NFS config details"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep -i username /etc/fstab 2>/dev/null; grep -i password /etc/fstab 2>/dev/null; grep -i cred /etc/fstab 2>/dev/null'
    local desc="VULNERABLE: looks like there are credentials in /etc/fstab"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    #local cmd='ls -la ~/.*_history 2>/dev/null'
    #local desc="Current user's history files"
    #run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='ls -la /root/.*_history 2>/dev/null'
    local desc="VULNERABLE: Root's history files are available"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    #local cmd='cat /etc/passwd | cut -d: -f6 | grep -v /proc$ | grep -v /dev$ | grep -v /sys$ | grep -v /bin$ | grep -v /usr/sbin$ | grep -v /$ | grep -v /sbin$ | xargs -iHOMEDIR find HOMEDIR -iname "*_history" 2>/dev/null | while read x; do echo && echo $x: && cat $x; done'
    local cmd='cat /etc/passwd | cut -d: -f6 | grep -v /proc$ | grep -v /dev$ | grep -v /sys$ | grep -v /bin$ | grep -v /usr/sbin$ | grep -v /$ | grep -v /sbin$ | xargs -iHOMEDIR find HOMEDIR -type f 2>/dev/null | grep "history$" | while read x; do echo && echo $x: && cat $x; done'
    local desc="All user's all history files"
    run_command "$cmd" "$desc" "$out" 

    local cmd='ls -la /var/mail 2>/dev/null'
    local desc="Any interesting mail in /var/mail"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='head -n100 /var/mail/root 2>/dev/null'
    local desc="We can read /var/mail/root (snippet below)"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache22/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null; ls -alhR /var/www/html/ 2>/dev/null'
    local desc="Anything on website? Maybe files with database info?"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    rm .guidfiles.tmp
    rm .suidfiles.tmp

    echo [+] Wrote output to: $out
    echo
}

################################################################################

find_passwords_etc () {
    local out="$RESULTDIR/passwords_etc_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Finding files that might contain passwords etc.| tee -a $out
    echo $LONGLINE>>$out

    generate_allfileslist

    local cmd='grep "\.pcap$" $ALLFILES'
    local desc="Found pcap files"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep "/core$" $ALLFILES'
    local desc="Found possible core dump files"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    if [ "$core_pattern" ] && [ "$core_pattern" != "core" ]; then
        local cmd='cat /proc/sys/kernel/core_pattern | xargs -i FPATTERN grep "/FPATTERN$" $ALLFILES'
        local desc="Found possible core dump files (core_pattern)"
        run_command "$cmd" "$desc" "$out" "silentfail" 
    fi

    local cmd='grep "\.MYD$" $ALLFILES'
    local desc="Possible database files found"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep "\.MYD$" $ALLFILES | grep -i "user\.MYD$" | while read x; do cp --backup=t $x $RESULTDIR && echo cp $x $RESULTDIR; done'
    local desc="Grab user.MYD"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep ".*\.xml$" $ALLFILES 2>/dev/null | xargs -iFILE grep -iH "\(<.*password>\|<.*passw>\|<.*pass>\|<.*pwd>\)" FILE 2>/dev/null'
    local desc="Possible passwords in xml files"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep "vnc\.ini$" $ALLFILES'
    local desc="Found pattern vnc.ini"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep "vnc$" $ALLFILES'
    local desc="Found pattern vnc"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep "\(_rsa$\|rsa\.pub$\|_dsa$\|_dsa\.pub$\|ssh_config$\|sshd_config$\|_keys$\|identity$\|identity.pub$\)" $ALLFILES | while read x; do cp --backup=t $x $RESULTDIR && echo cp $x $RESULTDIR; done'
    local desc="Grab interesting SSH files"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep -iw "accounts\|account" $ALLFILES | grep -v help | grep -v locale | grep -v openvas | grep -v icons'
    local desc="Found pattern account"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='grep ".*\.ini$\|.*\.inf$\|.*\.conf$\|.*\.log$\|.*\.sh$" $ALLFILES 2>/dev/null | xargs -iFILE grep -iH "\(password\|passw\|pass\|pwd\)[[:space:]]*[=]" FILE 2>/dev/null | grep -v exploitdb | grep -v openvas | grep -v samba-3\.4\.5 | grep -v \.ZAP | grep -v recon_scan'
    local desc="Possible passwords in ini, inf, conf, log or sh files"
    run_command "$cmd" "$desc" "$out" "silentfail" 

    local cmd='cat /etc/passwd | cut -d: -f6 | grep -v /proc$ | grep -v /dev$ | grep -v /sys$ | grep -v /bin$ | grep -v /usr/sbin$ | grep -v /$ | grep -v /sbin$ | xargs grep -D skip -IHr "\(password\|passw\|pass\|pwd\)[[:space:]]*[=]" 2>/dev/null | grep -v linloot | grep -v winloot | grep -v samba-3\.4\.5 | grep -v \.ZAP | grep -v recon_scan | grep -v pwk_hosts'
    local desc="Possible passwords in user's home directories"
    run_command "$cmd" "$desc" "$out" 

    echo [+] Wrote output to: $out
    echo
}

################################################################################

run_unix_privesc_check () {
    local out="$RESULTDIR/unix_privesc_check_$WHO.txt"
    echo $LONGLINE>$out
    echo [+] Running unix_privesc_check | tee -a $out
    echo $LONGLINE>>$out

    #local cmd='chmod +x unix-privesc-check.sh && ./unix-privesc-check.sh detailed 2>/dev/null'
    local cmd='chmod +x unix-privesc-check.sh && ./unix-privesc-check.sh standard 2>/dev/null'
    local desc="Running unix-privesc-check.sh"
    run_command "$cmd" "$desc" "$out" 

    echo [+] Wrote output to: $out
    echo
}


################################################################################

tarball_results () {
    echo [+] Generating tarball from results: $RESULTDIR

    local outfname=""
    local tgz="$RESULTDIR.tar.gz"
    local tbz="$RESULTDIR.tar.bz2"

    bz=$(which bzip2 2>/dev/null)
    if [ ! "$bz" ]; then
        outfname=$tgz
        tar -zcvf $tgz $RESULTDIR
    else
        outfname=$tbz
        tar -jcvf $tbz $RESULTDIR
    fi

    echo [+] Wrote: $outfname
    echo
}

################################################################################

tarball_linloot () {

    local tgz="linloot.tar.gz"
    local files="linloot.sh unix-privesc-check.sh nc_sendfile.sh nc_sendfile_server.sh nc_receivefile.sh nc_receivefile_client.sh netcat.pl httpserver.py nc_rshell.sh"

    tar -zcvf $tgz $files

    echo [+] Wrote: $tgz
    echo
}

################################################################################

main_menu () {
    echo
    echo "[u] Check user information"
    echo "[s] Check system information"
    echo "[c] Check cron jobs"
    echo "[n] Check networking information"
    echo "[p] Check processes and services"
    echo "[i] Check installed programs"
    echo "[f] Check file system information"
    echo "[b] Check interesting files"
    echo "[e] Find files that might contain passwords etc."
    echo "[d] Dump a list of all files"
    echo "[h] Run unix-privesc-check"
    echo "[z] Generate tarball from the results folder"
    echo "[a] Run all above"
    echo "[m] Make linloot tarball (prepare for upload)"
    echo "[x] Exit"
    echo

    local choice="x"
    read -p "Select [x]: " choice
    case $choice in
        u) check_userinfo;;
        s) check_sysinfo;;
        c) check_cron;;
        n) check_networkinfo;;
        p) check_processes;;
        i) check_programs;;
        f) check_filesystem;;
        b) check_interesting_files;; 
        e) find_passwords_etc;;
        d) generate_allfileslist;;
        h) run_unix_privesc_check;;
        z) tarball_results;; 
        a) do_all;;
        m) tarball_linloot;; 
       '') exit 0;; x) exit 0;;
        *) echo "Unknown option \"$choice\" - try again"; main_menu
    esac
}

################################################################################

do_all () {
    # First, generate the allfileslist
    generate_allfileslist
    # Run the following commands in parallel
    run_unix_privesc_check &
    find_passwords_etc &
    check_userinfo &
    check_sysinfo &
    check_cron &
    check_networkinfo &
    check_processes &
    check_programs &
    check_filesystem &
    check_interesting_files &
    wait

    tarball_results
}

################################################################################

# NOT USED CURRENTLY:
# We'll run a deep scan if $1 == "deep"
DEEP=$1
if [ "$DEEP" == "deep" ]; then DEEP=1; else DEEP=0; fi

setenv
mkdir -p $RESULTDIR
print_header
main_menu

################################################################################

