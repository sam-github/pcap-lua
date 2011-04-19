set -x
gcc -Wall -o tstpcap-git tstpcap.c -L/usr/local/lib -lpcap
gcc -Wall -o tstpcap-ubuntu tstpcap.c -lpcap

ldd tstpcap-git tstpcap-ubuntu
uname -a

sudo ./tstpcap-ubuntu eth0
sudo ./tstpcap-git eth0

