#!/system/bin/sh
# GhostLock-GOT-W29 hang diagnostic: run the root exe in the background,
# wait past the known hang point, dump every thread's kernel stack, then
# kill everything so the device stays usable.
cd /data/local/tmp/ghostlock-test || exit 1
OUT=/data/local/tmp/ghostlock-test/hang_diag.log
rm -f "$OUT" root_diag.log

POC_LOG_FILE=/data/local/tmp/ghostlock-test/root_diag.log \
GOT_FULL_RUN=1 GOT_VERIFY_WRITE=1 GOT_SLIDE_HOLD=1 GOT_SLIDE_ATTEMPTS=1 \
GOT_FAKELOCK_BSS=1 ./ghostlock_exe > /dev/null 2>&1 &
EXE=$!
echo "exe pid=$EXE started $(date +%T)" | tee -a "$OUT"

# KASLR ~7s + kernelsnitch ~60s + trigger ~3s -> hang ~75s.  Give it 100s.
sleep 100

echo "=== $(date +%T) process tree ===" | tee -a "$OUT"
ps -A -o PID,PPID,STAT,NAME 2>/dev/null | grep -E "ghostlock" | tee -a "$OUT"

for p in $EXE $(pgrep -f ghostlock_exe) $(pgrep -x ghostlock_exe); do
  [ -d "/proc/$p" ] || continue
  echo "=== pid $p ===" | tee -a "$OUT"
  for t in /proc/$p/task/*; do
    tid=${t##*/}
    st=$(cat /proc/$p/task/$tid/stat 2>/dev/null | cut -d' ' -f3)
    wc=$(cat /proc/$p/task/$tid/wchan 2>/dev/null)
    sc=$(cat /proc/$p/task/$tid/syscall 2>/dev/null)
    sp=$(grep -aE "^policy|^prio" /proc/$p/task/$tid/sched 2>/dev/null | tr '\n' ' ')
    echo "tid $tid state=$st wchan=$wc syscall=[$sc] sched[$sp]" | tee -a "$OUT"
    cat /proc/$p/task/$tid/stack 2>/dev/null | tee -a "$OUT"
    if [ "$st" = "D" ]; then
      echo "--- fdinfo of tid $tid ---" | tee -a "$OUT"
      for fd in /proc/$p/task/$tid/fd/*; do
        ls -l "$fd" 2>/dev/null | tee -a "$OUT"
      done
    fi
  done
done

echo "=== killing ===" | tee -a "$OUT"
killall ghostlock_exe 2>/dev/null
echo "done $(date +%T)" | tee -a "$OUT"
