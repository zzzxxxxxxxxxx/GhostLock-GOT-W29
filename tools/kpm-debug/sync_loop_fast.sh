#!/system/bin/sh
# fast pre-test sync loop: flush page cache every 0.5s so a panic/reboot
# loses at most the last half second of experiment logs.
while true; do
  sync
  sleep 0.5
done
