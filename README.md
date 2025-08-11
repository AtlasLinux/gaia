# gaia
Init for atlas linux project
This is Work In Progress (WIP) branch
## Setting up developer environment using distrobox
We use musl with clang, we would use alpine for best compatability with musl.
You need distrobox on your host system.
```
distrobox create -n CONTAINERNAME -i alpine
distrobox enter CONTAINERNAME
```
Set password and you are in container.

If you have problems with sudo se this distrobox issue: 
https://github.com/89luca89/distrobox/issues/899

Now we want to install some tools: 
```
sudo apk add musl musl-dev clang git nano make
```
Now you are ready to go, git clone this project and then you can compile it with make.
After compiling you can verify if its using musl using ldd build/init, if it uses musl it should print:
``/lib/ld-musl-x86_64.so.1: build/init: Not a valid dynamic program``,
it isnt dynamic beacuse we compile it with --static
