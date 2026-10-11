#!/usr/bin/env bash
# Reference: how the demo SIEM was set up on 2026-10-10 (Splunk in Docker Desktop on the user's
# Windows PC, Git Bash), for the wd2l receiver on the Raspberry Pi. Not part of any release.
# Secrets stay in ~/wd2l-splunk/secrets (outside the repo). Run step by step, not blindly.
set -euo pipefail
export MSYS_NO_PATHCONV=1                     # Git Bash: keep "/CN=..." and container paths as typed
REPO="$(git rev-parse --show-toplevel)"
W=~/wd2l-splunk
PC_IP=192.168.1.27                            # the HEC address the receiver uses (--hec-url)
IMAGE=splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4   # 10.6.0.5, amd64 only

# 1. Local CA and a HEC server cert. wd2l checks the hostname, so the SAN must match --hec-url.
mkdir -p $W/pki $W/secrets $W/app/wd2l/{local,default,metadata}
cd $W/pki
openssl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.pem -days 730 -subj "/CN=wd2l demo SIEM CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -nodes -keyout hec.key -out hec.csr -subj "/CN=wd2l-splunk-hec"
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:$PC_IP,IP:127.0.0.1,DNS:localhost\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > hec.ext
openssl x509 -req -in hec.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out hec.pem -days 730 -extfile hec.ext
cat hec.pem hec.key ca.pem > hec-splunk.pem   # Splunk's serverCert: cert, key, CA in one file

# 2. Two HEC tokens and the admin password.
uuid() { openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'; }
uuid > $W/secrets/hec.token; uuid > $W/secrets/hec-audit.token
openssl rand -base64 18 | tr -d '/+=' > $W/secrets/splunk-admin-password

# 3. The app: the repo's files, real tokens, the cert, app.conf, and export = system so the JSON
#    field extraction also works outside the app (notes A5-2).
S="$REPO/deploy/receiver/splunk"; A=$W/app/wd2l
cp "$S"/{authorize,fields,indexes,props,savedsearches}.conf $A/local/
sed -e "s/^token = 00000000-0000-0000-0000-000000000000/token = $(cat $W/secrets/hec.token)/" \
    -e "s/^token = 11111111-1111-1111-1111-111111111111/token = $(cat $W/secrets/hec-audit.token)/" \
    -e "s|^enableSSL = 1|enableSSL = 1\nserverCert = /opt/splunk/etc/auth/wd2l/hec-splunk.pem|" "$S/inputs.conf" > $A/local/inputs.conf
printf '[install]\nstate = enabled\n\n[ui]\nis_visible = true\nlabel = wd2l\n' > $A/default/app.conf
printf '[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n' > $A/metadata/local.meta

# 4. Splunk. Enterprise trial (Free turns off alerts and roles). UI and management on localhost
#    only; HEC on the LAN for the Pi. Running it accepts Splunk's license and General Terms.
docker volume create wd2l-splunk-etc; docker volume create wd2l-splunk-var
docker run -d --name wd2l-splunk --hostname wd2l-splunk --restart unless-stopped \
  -p 127.0.0.1:8000:8000 -p 127.0.0.1:8089:8089 -p 8088:8088 \
  -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD="$(cat $W/secrets/splunk-admin-password)" \
  -v wd2l-splunk-etc:/opt/splunk/etc -v wd2l-splunk-var:/opt/splunk/var "$IMAGE"
until [ "$(docker inspect -f '{{.State.Health.Status}}' wd2l-splunk)" = healthy ]; do sleep 10; done

# 5. Copy in the app and cert (docker.exe needs Windows paths), then restart splunkd only:
#    `docker restart` would re-run the image's provisioning.
docker exec -u root wd2l-splunk mkdir -p /opt/splunk/etc/auth/wd2l
docker cp "$(cygpath -w $W/pki/hec-splunk.pem)" wd2l-splunk:/opt/splunk/etc/auth/wd2l/hec-splunk.pem
docker cp "$(cygpath -w $W/app/wd2l)" wd2l-splunk:/opt/splunk/etc/apps/
docker exec -u root wd2l-splunk sh -c 'chown -R splunk:splunk /opt/splunk/etc/apps/wd2l /opt/splunk/etc/auth/wd2l && chmod 600 /opt/splunk/etc/auth/wd2l/hec-splunk.pem'
docker exec -u splunk wd2l-splunk /opt/splunk/bin/splunk restart
docker exec -u splunk wd2l-splunk /opt/splunk/bin/splunk btool inputs list http --debug | grep -E "serverCert|enableSSL"

# 6. The dashboard: Dashboard Studio JSON wrapped in a version-2 view, created over REST.
X=$W/wd2l_state_of_health.xml
{ printf '<dashboard version="2" theme="dark">\n<label>wd2l state of health</label>\n<definition><![CDATA[\n'
  cat "$S/wd2l-health-dashboard.json"; printf '\n]]></definition>\n</dashboard>\n'; } > $X
curl -sk -u "admin:$(cat $W/secrets/splunk-admin-password)" https://127.0.0.1:8089/servicesNS/nobody/wd2l/data/ui/views \
  -d name=wd2l_state_of_health --data-urlencode "eai:data@$(cygpath -w $X)"

# 7. On the receiver (the Pi): the CA and the tokens, root:wd2l 0640.
for f in hec.token hec-audit.token; do ssh pi5 "sudo install -m 640 -o root -g wd2l /dev/stdin /etc/wd2l/$f" < $W/secrets/$f; done
ssh pi5 "sudo install -m 640 -o root -g wd2l /dev/stdin /etc/wd2l/siem-ca.pem" < $W/pki/ca.pem
ssh pi5 "sudo curl -s --cacert /etc/wd2l/siem-ca.pem https://$PC_IP:8088/services/collector/health"   # HEC is healthy

# Searches from Git Bash: ~/wd2l-splunk/q.sh '<SPL without the leading "search">'
