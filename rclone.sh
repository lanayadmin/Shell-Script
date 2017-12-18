#!/bin/sh

# rclone status log
status_log="/var/log/rclone/rclone_status_"$(date +"%d%m%Y")".log"

# time date stamp
stamp() { echo $(date +"%d/%m/%Y %H:%M:%S"); }

# backup location from
backup="/backup/vmbackup_glob"

# backup location to
drserver="/backup/backup/vmbackup_glob"


start_sync() {
        stats=1
        echo "-- $(stamp) RCLONE SYNC STARTING--" >> $status_log
        rclone --log-file $status_log -v --retries 10 --dry-run sync $backup dr-server:$drserver

        if [ $? -eq 0 ]; then
                echo "1rclone sync completed $(stamp)" >> $status_log
        else
                while [ $stats -ne 10 ]
                do
                        echo "rclone sync failed.." >> $status_log
                        echo "try to ping remote server.." >> $status_log
                        ping -c 10 192.168.50.101 >> $status_log
                        echo "Attempting to rclone sync.." >> $status_log
                        rclone --log-file $status_log -v --retries 10 --dry-run sync $backup dr-server:$drserver

                        if [ $? -eq 0 ]; then
                                echo "2rclone sync completed $(stamp)" >> $status_log
                                break;
                        fi

                        $stats++;
                done
        fi
}
start_sync
