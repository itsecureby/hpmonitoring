#!/bin/bash

set -e
set -x

if [ $# -ne 2 ]
    then
        echo "Wrong number of arguments supplied."
        echo "Usage: $0 <server_url> <deploy_key>."
        exit 1
fi

server_url=$1
deploy_key=$2

# Install dependencies
apt update
apt --yes install \
    git \
    supervisor \
    build-essential \
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-3-dev \
    libpcap-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    python3 \
    python3-dev \
    python3-bson \
    python3-yaml \
    python3-boto3 

git clone https://github.com/DinoTools/dionaea.git 
cd dionaea

# Latest tested version with this install script
git checkout baf25d6

mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

make
make install

wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "dionaea"

cat > /opt/dionaea/etc/dionaea/ihandlers-enabled/hpfeeds.yaml <<EOF
- name: hpfeeds
  config:
    # fqdn/ip and port of the hpfeeds broker
    server: "$HPF_HOST"
    # port: $HPF_PORT
    ident: "$HPF_IDENT"
    secret: "$HPF_SECRET"
    # dynip_resolve: enable to lookup the sensor ip through a webservice
    dynip_resolve: "http://canhazip.com/"
    # Try to reconnect after N seconds if disconnected from hpfeeds broker
    # reconnect_timeout: 10.0
EOF


# Editing configuration for Dionaea.
mkdir -p /opt/dionaea/var/log/dionaea/wwwroot /opt/dionaea/var/log/dionaea/binaries /opt/dionaea/var/log/dionaea/log
chown -R nobody:nogroup /opt/dionaea/var/log/dionaea

mkdir -p /opt/dionaea/var/log/dionaea/bistreams 
chown nobody:nogroup /opt/dionaea/var/log/dionaea/bistreams

# Config for supervisor.
cat > /etc/supervisor/conf.d/dionaea.conf <<EOF
[program:dionaea]
command=/opt/dionaea/bin/dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg
directory=/opt/dionaea/
stdout_logfile=/opt/dionaea/var/log/dionaea.out
stderr_logfile=/opt/dionaea/var/log/dionaea.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

supervisorctl update

# Cowrie

apt-get install -y python python-dev git supervisor authbind openssl python-virtualenv build-essential python-gmpy2 libgmp-dev libmpfr-dev libmpc-dev libssl-dev python-pip libffi-dev

pip install -U supervisor
/etc/init.d/supervisor start || true

sed -i 's/#Port/Port/g' /etc/ssh/sshd_config
sed -i 's/Port 22$/Port 2222/g' /etc/ssh/sshd_config
service ssh restart
useradd -d /home/cowrie -s /bin/bash -m cowrie -g users

cd /opt
git clone https://github.com/micheloosterhof/cowrie.git cowrie
cd cowrie

# Most recent known working version
git checkout 34f8464

# Config for requirements.txt
cat > /opt/cowrie/requirements.txt <<EOF
twisted>=17.1.0
cryptography>=2.1
configparser
pyopenssl
pyparsing
packaging
appdirs>=1.4.0
pyasn1_modules
attrs
service_identity
python-dateutil
tftpy
bcrypt
EOF

virtualenv cowrie-env #env name has changed to cowrie-env on latest version of cowrie
source cowrie-env/bin/activate
# without the following, i get this error:
# Could not find a version that satisfies the requirement csirtgsdk (from -r requirements.txt (line 10)) (from versions: 0.0.0a5, 0.0.0a6, 0.0.0a5.linux-x86_64, 0.0.0a6.linux-x86_64, 0.0.0a3)
pip install csirtgsdk==0.0.0a6
pip install -r requirements.txt 

# Register sensor with MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "cowrie"

cd etc
cp cowrie.cfg.dist cowrie.cfg
sed -i 's/hostname = svr04/hostname = server/g' cowrie.cfg
sed -i 's/listen_endpoints = tcp:2222:interface=0.0.0.0/listen_endpoints = tcp:22:interface=0.0.0.0/g' cowrie.cfg
sed -i 's/version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2/version = SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3/g' cowrie.cfg
sed -i 's/#\[output_hpfeeds\]/[output_hpfeeds]/g' cowrie.cfg
sed -i '/\[output_hpfeeds\]/!b;n;cenabled = true' cowrie.cfg
sed -i "s/#server = hpfeeds.mysite.org/server = $HPF_HOST/g" cowrie.cfg
sed -i "s/#port = 10000/port = $HPF_PORT/g" cowrie.cfg
sed -i "s/#identifier = abc123/identifier = $HPF_IDENT/g" cowrie.cfg
sed -i "s/#secret = secret/secret = $HPF_SECRET/g" cowrie.cfg
sed -i 's/#debug=false/debug=false/' cowrie.cfg
cd ..

chown -R cowrie:users /opt/cowrie/
touch /etc/authbind/byport/22
chown cowrie /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22

# start.sh is deprecated on new Cowrie version and substituted by "bin/cowrie [start/stop/status]"
sed -i 's/AUTHBIND_ENABLED=no/AUTHBIND_ENABLED=yes/' bin/cowrie
sed -i 's/DAEMONIZE=""/DAEMONIZE="-n"/' bin/cowrie

# Config for supervisor
cat > /etc/supervisor/conf.d/cowrie.conf <<EOF
[program:cowrie]
command=/opt/cowrie/bin/cowrie start
directory=/opt/cowrie
stdout_logfile=/opt/cowrie/var/log/cowrie/cowrie.out
stderr_logfile=/opt/cowrie/var/log/cowrie/cowrie.err
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
user=cowrie
EOF

supervisorctl update

# snort 

INTERFACE=$(basename -a /sys/class/net/e*)


set -e
set -x

if [ $# -ne 2 ]
    then
        if [ $# -eq 3 ]
          then
            INTERFACE=$3
          else
            echo "Wrong number of arguments supplied."
            echo "Usage: $0 <server_url> <deploy_key>."
            exit 1
        fi

fi

compareint=$(echo "$INTERFACE" | wc -w)


if [ "$INTERFACE" = "e*" ] || [ "$compareint" -ne 1 ]
    then
        echo "No Interface selectable, please provide manually."
        echo "Usage: $0 <server_url> <deploy_key> <INTERFACE>"
        exit 1
fi

DEBIAN_FRONTEND=noninteractive apt-get -y install build-essential libpcap-dev libjansson-dev libpcre3-dev libdnet-dev libdumbnet-dev libdaq-dev flex bison python-pip git make automake libtool zlib1g-dev

pip install --upgrade distribute
pip install virtualenv

# Install hpfeeds and required libs...

cd /tmp
rm -rf libev*
wget https://github.com/pwnlandia/hpfeeds/releases/download/libev-4.15/libev-4.15.tar.gz
tar zxvf libev-4.15.tar.gz 
cd libev-4.15
./configure && make && make install
ldconfig

cd /tmp
rm -rf hpfeeds
git clone https://github.com/pwnlandia/hpfeeds.git
cd hpfeeds/appsupport/libhpfeeds
autoreconf --install
./configure && make && make install 

cd /tmp
rm -rf snort
git clone -b hpfeeds-support https://github.com/threatstream/snort.git
export CPPFLAGS=-I/include
cd snort
./configure --prefix=/opt/snort && make && make install 

# Register the sensor with the MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "snort"

mkdir -p /opt/snort/etc /opt/snort/rules /opt/snort/lib/snort_dynamicrules /opt/snort/lib/snort_dynamicpreprocessor /var/log/snort/
cd etc
cp snort.conf classification.config reference.config threshold.conf unicode.map /opt/snort/etc/
touch  /opt/snort/rules/white_list.rules
touch  /opt/snort/rules/black_list.rules

cd /opt/snort/etc/
# out prefix is /opt/snort not /usr/local...
sed -i 's#/usr/local/#/opt/snort/#' snort.conf 


# disable all the built in rules
sed -i -r 's,include \$RULE_PATH/(.*),# include $RULE_PATH/\1,' snort.conf

# enable our local rules
sed -i 's,# include $RULE_PATH/local.rules,include $RULE_PATH/local.rules,' snort.conf

# enable hpfeeds
sed -i "s/# hpfeeds/# hpfeeds\noutput log_hpfeeds: host $HPF_HOST, ident $HPF_IDENT, secret $HPF_SECRET, channel snort.alerts, port $HPF_PORT/" snort.conf 

#Set HOME_NET

IP=$(ip -f inet -o addr show $INTERFACE|head -n 1|cut -d\  -f 7 | cut -d/ -f 1)
sed -i "/ipvar HOME_NET/c\ipvar HOME_NET $IP" /opt/snort/etc/snort.conf

# Installing snort rules.
# mhn.rules will be used as local.rules.
rm -f /etc/snort/rules/local.rules
ln -s /opt/mhn/rules/mhn.rules /opt/snort/rules/local.rules

# Supervisor will manage snort-hpfeeds
apt-get install -y supervisor

# Config for supervisor.
cat > /etc/supervisor/conf.d/snort.conf <<EOF
[program:snort]
command=/opt/snort/bin/snort -c /opt/snort/etc/snort.conf -i $INTERFACE
directory=/opt/snort
stdout_logfile=/var/log/snort.log
stderr_logfile=/var/log/snort.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

cat > /etc/cron.daily/update_snort_rules.sh <<EOF
#!/bin/bash

mkdir -p /opt/mhn/rules
rm -f /opt/mhn/rules/mhn.rules.tmp

echo "[`date`] Updating snort signatures ..."
wget $server_url/static/mhn.rules -O /opt/mhn/rules/mhn.rules.tmp && \
	mv /opt/mhn/rules/mhn.rules.tmp /opt/mhn/rules/mhn.rules && \
	(supervisorctl update ; supervisorctl restart snort ) && \
	echo "[`date`] Successfully updated snort signatures" && \
	exit 0

echo "[`date`] Failed to update snort signatures"
exit 1
EOF
chmod 755 /etc/cron.daily/update_snort_rules.sh
/etc/cron.daily/update_snort_rules.sh

supervisorctl update


# p0f

INTERFACE=$(basename -a /sys/class/net/e*)


set -e
set -x

if [ $# -ne 2 ]
    then
        if [ $# -eq 3 ]
          then
            INTERFACE=$3
          else
            echo "Wrong number of arguments supplied."
            echo "Usage: $0 <server_url> <deploy_key>."
            exit 1
        fi

fi

compareint=$(echo "$INTERFACE" | wc -w)


if [ "$INTERFACE" = "e*" ] || [ "$compareint" -ne 1 ]
    then
        echo "No Interface selectable, please provide manually."
        echo "Usage: $0 <server_url> <deploy_key> <INTERFACE>"
        exit 1
fi

apt install -y git supervisor libpcap-dev libjansson-dev gcc

# install p0f
cd /opt
git clone https://github.com/threatstream/p0f.git
cd p0f
git checkout origin/hpfeeds
./build.sh
useradd -d /var/empty/p0f -M -r -s /bin/nologin p0f-user || true
mkdir -p -m 755 /var/empty/p0f

# Register the sensor with the MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "p0f"

# Note: This will change the interface and the ip in the p0f config
sed -i "/INTERFACE=/c\INTERFACE=$INTERFACE" /opt/p0f/p0f_wrapper.sh
sed -i "/MY_ADDRESS=/c\MY_ADDRESS=\$(ip -f inet -o addr show \$INTERFACE|head -n 1|cut -d\\\  -f 7 | cut -d/ -f 1)" /opt/p0f/p0f_wrapper.sh


cat > /etc/supervisor/conf.d/p0f.conf <<EOF
[program:p0f]
command=/opt/p0f/p0f_wrapper.sh
directory=/opt/p0f
stdout_logfile=/var/log/p0f.out         
stderr_logfile=/var/log/p0f.err          
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=TERM
environment=HPFEEDS_HOST="$HPF_HOST",HPFEEDS_PORT="$HPF_PORT",HPFEEDS_CHANNEL="p0f.events",HPFEEDS_IDENT="$HPF_IDENT",HPFEEDS_SECRET="$HPF_SECRET"
EOF

supervisorctl update

