---
title:  "How To: Remote Development on VSCode using SSH"
layout: post
---


My personal setup at home includes several machines: a Windows 11 machine and a Linux based home server. Now while Windows 11 is perfect for web browsing and occasional gaming, the bulk of my time is spent writing and compiling code and Windows is not the ideal environment for that. This is where the "Remote SSH" plugin for VSCode comes in handy. It allows you to use your VSCode running on Windows as if It was running on your Linux machine.

Below are the required configuration steps:

1.  On you Windows machine, generate SSH key pair. Open PowerShell and run the following command:
    > ssh-keygen -b 4096
    
    By default this will generate two keys under `c:/Users/<user name>/.ssh/`
    Copy the public key [content of id_rsa.pub].

2.	On your Linux machine, run the following command to create authorized_keys file:
    > vim ~/.ssh/authorized_keys
    Paste the public key from earlier step.
    
3.  Install `Remote SSH` plugin for VSCode.
    
    ![Remote SSH Plugin](/assets/2022-15-10-how-to-remote-development-on-vscode-using-ssh/remote_ssh_plugin.png)

4.  To configure the plugin, click `ctrl + shift + p` and type `ssh config`.  Open the configuration file and fill it with the following [adjusted with your IP addresses and etc]:
    ```
    Host 192.168.1.10
      HostName 192.168.1.10
      User navadiaev
      Port 22
      PreferredAuthentications publickey
      IdentityFile "C:\Users\nafta\.ssh\id_rsa"
    ```
    
5.  Click `ctrl + shift + p` again and type `connect to host`. 
    You should be able to select the host you just configured and login.
    

Below is a video where I execute the above instructions:


    
