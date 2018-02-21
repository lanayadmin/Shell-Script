#!/bin/sh
# rclone status log
status_log="/var/log/rclone/rclone_status_"$(date +"%d%m%Y")".log"

# time date stamp
stamp() { echo $(date +"%d/%m/%Y %H:%M:%S"); }

# backup location from
backup="/backup"

# backup location to
drserver="/backup/rclone"

start_sync(){

        stats=1
        echo "-- $(stamp) RCLONE SYNC STARTING--" >> $status_log
        rclone --log-file $status_log -v --retries 10 --delete-before sync $backup dr-server:$drserver

        if [ $? -eq 0 ]; then
                echo "1rclone sync completed $(stamp)" >> $status_log

        else
                while [ $stats -ne 10 ]
                do
                        echo "rclone sync failed.." >> $status_log
                        echo "try to ping remote server.." >> $status_log
                        ping -c 10 192.168.2.253 >> $status_log
                        echo "Attempting to rclone sync.." >> $status_log
                        rclone --log-file $status_log -v --retries 10 --delete-before sync $backup dr-server:$drserver

                        if [ $? -eq 0 ]; then
                                echo "2rclone sync completed $(stamp)" >> $status_log
                                break
                        fi

                        let "stats++"
                done
        fi
}

check_duplicate_process() {

        count_process=`pgrep rclone | wc -l`;

        while [[ $count_process -ge 3 ]]
        do
                echo "$(stamp) Rclone is currently running.. wait for it to be finished.. sleep 30 minutes.." >> /var/log/rclone/debug_$(date +"%d%m%Y");
                sleep 10s
                count_process=`pgrep rclone | wc -l`
        done

        start_sync
}

check_duplicate_process
