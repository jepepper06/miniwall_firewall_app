# Windows Staful Firewall Prototype
The current firewall implements blacklist blocking policy
and does persistent blocking of apps in network. It has 2
parts the firewall itself and a daemon designed to be ran 
when system starts.
## The daemon
The daemon binaries reads db information on blocked apps
and apply the filters on network layer.
## The Firewall
The firewall uses Windows Filtering Platform to block apps in network
based in a blacklist policy. It is designed to work for windows system.
It save data to a sqlite db that is readen when system starts.
### Notes about compiling and running
You will need to install CMake tools, because projects depends on a C function,
I tried several times to translate this function to rust, I wasted like half a day in
it, then decided to move ahead with project and use CMake tool to use this C function in my project.