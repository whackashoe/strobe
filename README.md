#Strobe
## strobe - Super optimised TCP port surveyor

DESCRIPTION
Strobe is a network/security tool that locates and describes all listening tcp ports on a (remote) host or on many hosts in a bandwidth utilisation maximising, and process resource minimising manner. Strobe approximates a parallel finite state machine internally. In non-linear multi-host mode it attempts to apportion bandwidth and sockets among the hosts very efficiently.  This can reap appreciable gains in speed for multiple distinct hosts/routes.

On a machine with a reasonable number of sockets, strobe is fast enough to port scan entire Internet sub domains. It is even possible to survey an entire small country in a reasonable time from a fast machine on the network  backbone, provided the machine in question uses dynamic socket allocation or has had  its  static  socket  allocation  increased  very appreciably  (check your kernel options). In this very limited applica-tion strobe is said to be faster than ISS2.1 (a high quality commercial security  scanner by cklaus@iss.net and friends) or PingWare (also com-mercial). Strobe is now rather OUTDATED and newer port scanner's do exist (see nmap).


## Quick Start
```bash
  git clone https://github.com/brendoncdrew/strobe.git
  cd strobe
  make
  make install
```

NOTE: sudo make install to install for ALL users
