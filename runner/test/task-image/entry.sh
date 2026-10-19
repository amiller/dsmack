# NDJSON over stdin/stdout: echoes each line; {"op":"later"} prints two lines 2 s later, {"op":"flood"} prints
# 5 MiB + newline 2 s later, {"op":"exit"} writes /out and exits 0.
echo '{"ready":true}'
while IFS= read -r line; do
  case "$line" in
    *'"op":"later"'*) (sleep 2; echo '{"later":1}'; echo '{"later":2}') & ;;
    *'"op":"flood"'*) (sleep 2; head -c 5242880 /dev/zero | tr '\0' x; echo) & ;;
    *'"op":"exit"'*) break ;;
    *) echo "$line" ;;
  esac
done
mkdir -p /out/sub
cp /in/hello.txt /out/in-copy.txt
ls /sys/class/net > /out/net.txt
touch /in/x 2> /out/in-write.txt; echo "exit=$?" >> /out/in-write.txt
echo '{"result":"ok"}' > /out/result.json
printf 'nested\n' > /out/sub/a.txt
d=/out/deep/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
mkdir -p $d; echo long > $d/f.txt
printf '#!/bin/sh\n' > /out/run.sh; chmod 755 /out/run.sh
sync
echo '{"done":true}'
