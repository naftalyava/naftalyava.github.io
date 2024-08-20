---
layout: post
title: "How to Set Up Open vSwitch & QEMU/KVM for Your Virtualization Home Lab"
date: 2024-05-13
categories: tutorial virtualization
---


## Introduction

Today, we're addressing a common challenge for home lab users: how to make the most of our server with multiple cores and significant memory. Whether you're running a Plex server, Kubernetes clusters, or VMs for development, a frequent issue is that these VMs are often hidden behind NAT, limiting their accessibility from other devices on your network.

### Tools Overview

To solve this, we will use two open source projects:

1. **QEMU/KVM**: This hypervisor and virtual machine monitor lets us create and manage VMs.
2. **Open vSwitch (OVS)**: This is a software-based switch that enables more complex network configurations in virtualized environments than traditional switches.

## Understanding the Problem

The main issue is that VMs operating behind NAT are not directly accessible from other machines on your home network, which can restrict your ability to interact with these VMs from other devices.

## Implementing the Solution

Here’s how to configure your VMs to be accessible within your network using Open vSwitch and QEMU/KVM.

### Step 1: Setting Up Open vSwitch

1. **Install Open vSwitch**:
   ```bash
   sudo apt-get install openvswitch-switch
   ```
2. **Create a Virtual Switch**:
   ```bash
   sudo ovs-vsctl add-br vm_net
   ```

3. **Verify the Bridge**:
   ```bash
   sudo ovs-vsctl show
   ```
   Ensure your newly created virtual bridge `vm_net` is listed.

### Step 2: Configuring Network Interface

We now link our network interface to the virtual bridge to allow VMs to communicate with the home network.

1. **Add Network Interface to the Bridge**:
   ```bash
   sudo ovs-vsctl add-port vm_net eth0
   ```
   Replace `eth0` with the correct identifier for your network interface.

2. **Check Configuration**:
   ```bash
   sudo ovs-vsctl show
   ```
   Make sure the network interface is correctly integrated with the bridge.

### Step 3: Adjusting VM Network Settings

We need to ensure that the VMs utilize the Open vSwitch bridge for network communication.

1. **Update VM Network Config**:
   Adjust your VM's network configuration to connect through the `vm_net` bridge:
   ```xml
   <interface type="bridge">
      <source bridge="vm_net"/>
      <virtualport type="openvswitch"></virtualport>
      <model type="e1000e"/>
   </interface>
   ```
2. **Restart the VM**:
   ```bash
   sudo virsh start <vm-name>
   ```

## Verifying the Setup

After these configurations, your VM should receive an IP address from your home DHCP server. Check the VM's network details and try to ping the VM from another device in your network to ensure connectivity.

## Conclusion

By integrating QEMU/KVM with Open vSwitch, you've overcome the NAT limitations, making your VMs fully accessible within your network. This configuration not only simplifies network management but also enhances the usability of your home lab.

If you prefer to consume this post as a video, I got you covered:
<iframe width="560" height="315" src="https://www.youtube.com/embed/vVcU_Lpju2o?si=cMYbcTJihWgsCH3y" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>