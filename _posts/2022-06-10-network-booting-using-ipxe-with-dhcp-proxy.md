---
title:  "Network Booting Using iPXE With DHCP Proxy"
layout: post
---

In this short post I am going to explain how to setup an iPXE server with a DHCP proxy, meaning you will not need to configure anything on the existing DHCP server you have on the network. This comes especially handy when you can't control/modify the existing DHCP server.

Lets dive into the setup instructions. In case you will want to understand a bit more how it all works, I will be uploading a youtube video which explains the configuration provided in this post.

1.	Install dnsmasq:
    > sudo apt-get install dnsmasq

2.	Get ipxe from https://ipxe.org/download, you can get the source code and compile yourself or just download the precompiled binaries. You can also download all the files needed from link at the end of this post. The file you will need from this step is ipxe.efi, it needs to be placed in the root folder of your tftp server.

3.	Download Ubuntu Live 22.04 ISO, from www.ubuntu.com and from the iso image retrieve /casper/initrd and /casper/vmlinuz files. Create folder "casper" at the root folder of your tftp server, and copy both of these files there.

4.	You also should create grub/grub.cfg configuration file under your root tftp folder. This file is defines the boot menu you see once your iPXE client boots. Below is an example where we use our iPXE server to boot a Ubuntu ISO image from Ubuntu web servers:

    ```
    menuentry "Install Ubuntu 22.04 (Pull the iso from web)" {
       set gfxpayload=keep
       linux   /casper/vmlinuz url=https://releases.ubuntu.com/jammy/ubuntu-22.04.1-desktop-amd64.iso only-ubiquity ip=dhcp ---
       initrd  /casper/initrd
    }
    ```


    Assuming the root folder of your tftp server is /tftpboot, the folder structure should look like this:

    ```
    /tftpboot/
    ├── casper
    │   ├── initrd
    │   └── vmlinuz
    ├── grub
    │   └── grub.cfg
    ├── grubnetx64.efi.signed
    └── ipxe.efi
    ```
    

5.  Configure dnsmasq, to enable DHCP proxy, TFTP server and all required configurations on how to recognize clients and provide them with needed boot files.
    Here is an example configuration [/etc/dnsmasq.conf], edit it per your environment and needs:
    ```
    # Debug logging
    log-debug


    # Disable DNS server
    port=0


    dhcp-range=192.168.1.10,proxy,255.255.255.0


    dhcp-no-override

    # this is the interface on which dnsmasq listens 
    interface=vm_network


    # if we detected ipxe client we want to tag it, so we will provide a different boot file
    dhcp-match=set:ipxe-efi,175,36
    tag-if=set:ipxe-ok,tag:ipxe-efi


    # we want to load ipxe firmware on first boot
    pxe-service=tag:!ipxe-ok,X86-64_EFI,PXE,ipxe.efi,192.168.1.10


    # on second boto we already booted with the ipxe firmware, now we can use grub
    dhcp-boot=tag:ipxe-ok,grubnetx64.efi.signed,,192.168.1.10


    # enable tftp server and configure location
    enable-tftp
    tftp-root=/tftpboot
    ```

6.	Now we ready to restart dnsmasq service by running:
    ```
    sudo systemctl restart dnsmasq.service
    ```
    

If all goes well, you should see the following menu once you boot a pxe capable client:

![grub menu](/assets/2022-06-10-network-booting-using-ipxe-with-dhcp-proxy/ipxe_boot_menu.png)


Below is the video with more in depth explanations.

<iframe width="1227" height="690" src="https://www.youtube.com/embed/cc4Hb6dpbs8" title="Network Booting Using iPXE With DHCP Proxy" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>


    
