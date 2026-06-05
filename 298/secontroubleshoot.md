Below is a **read-only troubleshooting command set** I would run on each Security Onion node: Manager, Search, ManagerSearch, Heavy, Standalone, Sensor, and Receiver. Security Onion normally tries to use most available disk and may keep writing until roughly **80–90% usage** before purging old data; the usual big consumers are **Elasticsearch indexed data** and **Suricata full packet capture**. ([Security Onion Documentation][1])

Security Onion’s current docs identify `/nsm` as the main data area, with Elasticsearch under `/nsm/elasticsearch`, Suricata full packet capture under `/nsm/suripcap`, Zeek logs under `/nsm/zeek`, and debug logs under `/opt/so/log`. ([Security Onion Documentation][2]) For airgap installs, also check `/nsm/repo` because install/update RPM packages are copied there from the ISO, and rules are copied under `/nsm/rules/...`. ([Security Onion Documentation][3])

## 1. Fast triage: run this first on each node

This creates a local report at `/tmp/so-disk-triage-<hostname>-<timestamp>.log`.

```bash
sudo bash -c '
OUT="/tmp/so-disk-triage-$(hostname -s)-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$OUT") 2>&1

echo "===== IDENTITY ====="
hostname -f
date -u
cat /etc/os-release 2>/dev/null | head -5
echo

echo "===== SECURITY ONION STATUS ====="
so-status || true
echo

echo "===== FILESYSTEMS / INODES ====="
df -hT --total
echo
df -ih
echo

echo "===== BLOCK DEVICES / MOUNTS / LVM ====="
lsblk -e7 -o NAME,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS,UUID
echo
findmnt -D
echo
pvs 2>/dev/null || true
vgs 2>/dev/null || true
lvs -a -o+devices 2>/dev/null || true
echo

echo "===== TOP SECURITY ONION DATA DIRECTORIES ====="
for d in /nsm /nsm/elasticsearch /nsm/suripcap /nsm/zeek /nsm/strelka /nsm/repo /nsm/rules /opt/so /opt/so/log /var/lib/docker /var/log; do
  if [ -e "$d" ]; then
    echo
    echo "### $d"
    ionice -c3 nice -n19 du -xhd1 "$d" 2>/dev/null | sort -h
  fi
done

echo
echo "===== LARGEST FILES IN COMMON HOTSPOTS ====="
for d in /nsm /opt/so/log /var/log /var/lib/docker; do
  if [ -e "$d" ]; then
    echo
    echo "### $d"
    ionice -c3 nice -n19 find "$d" -xdev -type f -printf "%s\t%TY-%Tm-%Td %TH:%TM\t%p\n" 2>/dev/null \
      | sort -nr | head -40 | numfmt --field=1 --to=iec
  fi
done

echo
echo "===== OPEN DELETED FILES: df FULL BUT du DOES NOT MATCH ====="
lsof +L1 2>/dev/null | sort -k7 -n | tail -50 || true

echo
echo "===== DOCKER DISK USAGE ====="
docker system df -v 2>/dev/null || true
echo
docker ps -a --size --format "table {{.Names}}\t{{.Status}}\t{{.Size}}\t{{.Image}}" 2>/dev/null || true
echo
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}" 2>/dev/null || true

echo
echo "===== ELASTICSEARCH HEALTH / DISK / INDICES ====="
so-elasticsearch-query "_cluster/health?pretty" 2>/dev/null || true
echo
so-elasticsearch-query "_cat/allocation?v" 2>/dev/null || true
echo
so-elasticsearch-query "_cat/nodes?v&h=name,roles,disk.total,disk.used,disk.avail,disk.used_percent,heap.percent,ram.percent,cpu,load_1m" 2>/dev/null || true
echo
so-elasticsearch-query "_cat/indices?v&s=store.size:desc&h=health,status,index,pri,rep,docs.count,store.size,pri.store.size" 2>/dev/null || true
echo
so-elasticsearch-query "_cat/shards?v&s=store:desc&h=index,shard,prirep,state,docs,store,node" 2>/dev/null || true
echo
so-elasticsearch-indices-growth 2>/dev/null || true
echo
so-elasticsearch-retention-estimate 2>/dev/null || true

echo
echo "===== RECENT SYSTEM / SO LOG CLUES ====="
journalctl --disk-usage 2>/dev/null || true
echo
journalctl -p warning..alert --since "24 hours ago" --no-pager 2>/dev/null | tail -300 || true
echo
grep -RHEi "no space|disk|watermark|flood|read[-_ ]only|unassigned|retention|delete|error|failed|rejected" \
  /opt/so/log /nsm/zeek/logs /nsm/strelka/log 2>/dev/null | tail -500 || true

echo
echo "Report saved to: $OUT"
'
```

## 2. Basic disk, mount, LVM, and inode commands

Use these when you want the short version rather than the full report.

```bash
hostname -f
date -u
sudo so-status

df -hT --total
df -ih
lsblk -e7 -o NAME,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS,UUID
findmnt -D

sudo pvs
sudo vgs
sudo lvs -a -o+devices
```

Security Onion’s ISO uses LVM by default, and the current docs show `/nsm` commonly using XFS; their supported expansion workflow starts with checking filesystems using `df -Th` and LVM using `pvdisplay`, `vgdisplay`, and `lvdisplay`. ([Security Onion Documentation][4])

## 3. Find which top-level directories are consuming space

Start with `/nsm` and `/opt/so/log`.

```bash
sudo du -xhd1 / 2>/dev/null | sort -h
sudo du -xhd1 /nsm 2>/dev/null | sort -h
sudo du -xhd1 /opt/so 2>/dev/null | sort -h
sudo du -xhd1 /opt/so/log 2>/dev/null | sort -h
```

Check the known Security Onion hotspots:

```bash
sudo du -sh /nsm/elasticsearch 2>/dev/null
sudo du -sh /nsm/suripcap 2>/dev/null
sudo du -sh /nsm/zeek 2>/dev/null
sudo du -sh /nsm/strelka 2>/dev/null
sudo du -sh /nsm/repo 2>/dev/null
sudo du -sh /nsm/rules 2>/dev/null
sudo du -sh /var/lib/docker 2>/dev/null
sudo du -sh /var/log 2>/dev/null
```

Then drill into the large ones:

```bash
sudo ionice -c3 nice -n19 du -xhd2 /nsm 2>/dev/null | sort -h | tail -100
sudo ionice -c3 nice -n19 du -xhd2 /nsm/elasticsearch 2>/dev/null | sort -h | tail -100
sudo ionice -c3 nice -n19 du -xhd2 /nsm/suripcap 2>/dev/null | sort -h | tail -100
sudo ionice -c3 nice -n19 du -xhd2 /nsm/zeek 2>/dev/null | sort -h | tail -100
sudo ionice -c3 nice -n19 du -xhd2 /nsm/strelka 2>/dev/null | sort -h | tail -100
sudo ionice -c3 nice -n19 du -xhd2 /opt/so/log 2>/dev/null | sort -h | tail -100
```

## 4. Find the largest individual files

```bash
sudo ionice -c3 nice -n19 find /nsm -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec

sudo ionice -c3 nice -n19 find /opt/so/log -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec

sudo ionice -c3 nice -n19 find /var/log -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec
```

Find very large files anywhere on the root filesystem:

```bash
sudo find / -xdev -type f -size +1G -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | numfmt --field=1 --to=iec
```

## 5. Check Elasticsearch disk, index, shard, and retention state

Run these from the Manager or a node where `so-elasticsearch-query` works. Security Onion documents `so-elasticsearch-query` as the CLI method for querying local Elasticsearch. ([Security Onion Documentation][5])

```bash
sudo so-elasticsearch-query '_cluster/health?pretty'

sudo so-elasticsearch-query '_cat/allocation?v'

sudo so-elasticsearch-query '_cat/nodes?v&h=name,roles,disk.total,disk.used,disk.avail,disk.used_percent,heap.percent,ram.percent,cpu,load_1m'

sudo so-elasticsearch-query '_cat/indices?v&s=store.size:desc&h=health,status,index,pri,rep,docs.count,store.size,pri.store.size'

sudo so-elasticsearch-query '_cat/shards?v&s=store:desc&h=index,shard,prirep,state,docs,store,ip,node'

sudo so-elasticsearch-query '_cat/shards?v' | grep -E 'UNASSIGNED|INITIALIZING|RELOCATING'
```

Security Onion also provides helper commands for index/shard review and growth/retention estimates:

```bash
sudo so-elasticsearch-indices-list
sudo so-elasticsearch-shards-list
sudo so-elasticsearch-indices-growth
sudo so-elasticsearch-retention-estimate
```

Those are especially important on multi-node deployments: Security Onion’s docs warn that if ILM is not configured to delete indices before the Elasticsearch disk watermark, Elasticsearch may stop ingesting. They also note that `so-elasticsearch-indices-growth` and `so-elasticsearch-retention-estimate` are useful for determining daily ingestion and projected retention. ([Security Onion Documentation][6])

Look for Elasticsearch disk/watermark errors:

```bash
sudo grep -RHEi 'watermark|flood|read[-_ ]only|disk|no space|unassigned|rejected|circuit|retention|delete' \
  /opt/so/log/elasticsearch 2>/dev/null | tail -300

sudo docker logs --tail 300 so-elasticsearch 2>&1 | egrep -i 'watermark|flood|read|disk|space|unassigned|rejected|error|failed'
```

Security Onion documents Elasticsearch logs under `/opt/so/log/elasticsearch/` and also recommends Docker logs for the container when needed. ([Security Onion Documentation][6])

## 6. Check Suricata full packet capture usage

Security Onion now uses Suricata for full packet capture; the docs say Suricata writes standard PCAP files and that full packet capture can be configured under `Suricata -> config -> pcap`, including a `maxsize` option for total PCAP disk usage. ([Security Onion Documentation][7])

```bash
sudo du -sh /nsm/suripcap 2>/dev/null
sudo du -xhd2 /nsm/suripcap 2>/dev/null | sort -h | tail -100

sudo find /nsm/suripcap -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec
```

Summarize PCAP growth by day:

```bash
sudo find /nsm/suripcap -xdev -type f -printf '%TY-%Tm-%Td\t%s\n' 2>/dev/null \
  | awk '{bytes[$1]+=$2} END {for (d in bytes) print bytes[d], d}' \
  | sort -nr | head -30 | numfmt --field=1 --to=iec
```

Check Suricata logs:

```bash
sudo tail -200 /opt/so/log/suricata/suricata.log 2>/dev/null

sudo grep -RHEi 'pcap|disk|space|maxsize|drop|dropped|capture|error|failed' \
  /opt/so/log/suricata 2>/dev/null | tail -300

sudo docker logs --tail 300 so-suricata 2>&1 | egrep -i 'pcap|disk|space|maxsize|drop|capture|error|failed'
```

Security Onion points to `/opt/so/log/suricata/suricata.log` and Docker logs for Suricata troubleshooting. ([Security Onion Documentation][8])

## 7. Check Zeek log growth

Zeek logs are stored under `/nsm/zeek/logs`, collected by Elastic Agent, parsed/stored in Elasticsearch, and available in Dashboards, Hunt, and Kibana. ([Security Onion Documentation][9])

```bash
sudo du -sh /nsm/zeek 2>/dev/null
sudo du -xhd2 /nsm/zeek/logs 2>/dev/null | sort -h | tail -100

sudo find /nsm/zeek/logs -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec
```

Check Zeek diagnostics:

```bash
sudo tail -200 /nsm/zeek/logs/current/reporter.log 2>/dev/null
sudo tail -200 /nsm/zeek/logs/current/stats.log 2>/dev/null
sudo tail -200 /nsm/zeek/logs/current/stderr.log 2>/dev/null

sudo grep -RHEi 'disk|space|error|failed|dropped|loss|packet|capture' \
  /nsm/zeek/logs 2>/dev/null | tail -300

sudo docker logs --tail 300 so-zeek 2>&1 | egrep -i 'disk|space|error|failed|drop|loss|packet'
```

Security Onion documents Zeek diagnostic logs under `/nsm/zeek/logs/`, including `reporter.log`, `stats.log`, `stderr.log`, and `stdout.log`, and recommends Docker logs when needed. ([Security Onion Documentation][10])

## 8. Check Strelka extracted-file data

Strelka-analyzed files end up under `/nsm/strelka/processed/`, and Strelka diagnostic logs are under `/nsm/strelka/log/`. ([Security Onion Documentation][11])

```bash
sudo du -sh /nsm/strelka 2>/dev/null
sudo du -xhd2 /nsm/strelka 2>/dev/null | sort -h | tail -100

sudo find /nsm/strelka -xdev -type f -printf '%s\t%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null \
  | sort -nr | head -100 | numfmt --field=1 --to=iec

sudo grep -RHEi 'disk|space|error|failed|queue|processed' \
  /nsm/strelka/log 2>/dev/null | tail -300

for c in so-strelka-backend so-strelka-coordinator so-strelka-filestream so-strelka-frontend so-strelka-manager; do
  echo "### $c"
  sudo docker logs --tail 100 "$c" 2>&1 | egrep -i 'disk|space|error|failed|queue|processed' || true
done
```

## 9. Check Docker images, containers, logs, and registry

Security Onion includes Docker engine and images in the ISO, and the docs show `sudo docker images` for listing installed images. ([Security Onion Documentation][12]) Docker’s own CLI docs describe `docker system df` as the command that displays Docker daemon disk usage. ([Docker Documentation][13])

```bash
sudo docker system df -v

sudo docker ps -a --size --format 'table {{.Names}}\t{{.Status}}\t{{.Size}}\t{{.Image}}'

sudo docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}'

sudo du -sh /var/lib/docker 2>/dev/null
sudo du -xhd1 /var/lib/docker 2>/dev/null | sort -h

sudo du -sh /nsm/docker-registry 2>/dev/null
sudo du -xhd1 /nsm/docker-registry 2>/dev/null | sort -h
```

Check individual container logs only as needed:

```bash
sudo docker logs --tail 200 so-elasticsearch
sudo docker logs --tail 200 so-logstash
sudo docker logs --tail 200 so-suricata
sudo docker logs --tail 200 so-zeek
sudo docker logs --tail 200 so-kibana
sudo docker logs --tail 200 so-soc
```

Security Onion notes that most container logs are redirected to application log directories under `/opt/so/log`, but some cases require `docker logs <container-name>`. ([Security Onion Documentation][1])

## 10. Check logs and journald for “disk full” symptoms

```bash
sudo journalctl --disk-usage

sudo journalctl -p warning..alert --since "24 hours ago" --no-pager | tail -300

sudo grep -RHEi 'no space left|disk full|disk|watermark|flood|read[-_ ]only|unassigned|failed|error|rejected|retention|deleted' \
  /opt/so/log /var/log /nsm/zeek/logs /nsm/strelka/log 2>/dev/null | tail -500
```

Security Onion Console logs are under `/opt/so/log/soc/`, and SOC auth/Kratos logs are under `/opt/so/log/kratos/`. ([Security Onion Documentation][14])

## 11. Check for open deleted files

This catches the classic case where `df` shows full but `du` cannot find the space because a running process still has a deleted file open.

```bash
sudo lsof +L1

sudo lsof +L1 2>/dev/null | awk 'NR==1 || $7 > 104857600 {print}' | sort -k7 -n
```

## 12. Interpret the likely root cause

Use this decision path:

| Finding                                           | Likely cause                                                             | Next place to look                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `/nsm/elasticsearch` is biggest                   | Indexed logs/metadata retention too long or ILM not deleting fast enough | `so-elasticsearch-indices-growth`, `so-elasticsearch-retention-estimate`, `_cat/indices`, `_cat/allocation` |
| `/nsm/suripcap` is biggest                        | Full packet capture retention/`maxsize` too high for traffic volume      | Suricata PCAP `maxsize`, traffic volume, BPF/conditional PCAP                                               |
| `/nsm/zeek/logs` is biggest                       | Zeek logs not being consumed/rotated or very high metadata volume        | Zeek `reporter.log`, `stats.log`, Elastic Agent/Logstash errors                                             |
| `/nsm/strelka` is biggest                         | File extraction volume or Strelka backlog                                | Strelka processed/log dirs and container logs                                                               |
| `/nsm/repo` or `/nsm/rules` is unexpectedly large | Airgap ISO repo/rules/custom local archives accumulating                 | Airgap update media/rule archives                                                                           |
| `/var/lib/docker` is biggest                      | Docker images, layers, container logs, or volumes                        | `docker system df -v`, `docker ps -a --size`, image list                                                    |
| `df` full but `du` small                          | Deleted open files                                                       | `lsof +L1`, restart the owning process only after identifying it                                            |

Do not delete indices, PCAP, Docker layers, or logs until you know which category is causing growth. On Security Onion, deleting the wrong data directly from disk can create inconsistent Elasticsearch, Docker, or sensor state.

[1]: https://docs.securityonion.net/en/3/main/faq/ "FAQ - Security Onion Documentation"
[2]: https://docs.securityonion.net/en/3/main/directory/ "Directory - Security Onion Documentation"
[3]: https://docs.securityonion.net/en/3/main/airgap/ "Airgap - Security Onion Documentation"
[4]: https://docs.securityonion.net/en/3/main/new-disk/ "New Disk - Security Onion Documentation"
[5]: https://docs.securityonion.net/en/3/main/so-elasticsearch-query/ "so-elasticsearch-query - Security Onion Documentation"
[6]: https://docs.securityonion.net/en/3/main/elasticsearch/ "Elasticsearch - Security Onion Documentation"
[7]: https://docs.securityonion.net/en/3/main/full-packet-capture/ "Full Packet Capture - Security Onion Documentation"
[8]: https://docs.securityonion.net/en/3/main/suricata/ "Suricata - Security Onion Documentation"
[9]: https://docs.securityonion.net/en/3/main/zeek/?utm_source=chatgpt.com "Zeek"
[10]: https://docs.securityonion.net/en/3/main/zeek/ "Zeek - Security Onion Documentation"
[11]: https://docs.securityonion.net/en/3/main/strelka/ "Strelka - Security Onion Documentation"
[12]: https://docs.securityonion.net/en/3/main/docker/ "Docker - Security Onion Documentation"
[13]: https://docs.docker.com/reference/cli/docker/system/df/ "docker system df | Docker Docs"
[14]: https://docs.securityonion.net/en/3/main/security-onion-console-logs/ "Security Onion Console Logs - Security Onion Documentation"
