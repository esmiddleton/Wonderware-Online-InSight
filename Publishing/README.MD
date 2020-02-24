Publisher Diagnostics
=====================

Typical control network architectures create a lot of obstacles for publishing data to AVEVA Insight. To help diagnose problems with network and/or on-premises components working with AVEVA Insight, use the Powershell scripts.

DMZ
---
Although these tools can be useful in other architectures, they assume the Publisher is deployed behind a DMZ which protects against general Internet access and that a web proxy, such as AVEVA's [DMZ Secure Link](https://online.wonderware.com/Downloads/InsightPublisher/DMZSecureLink.zip "free DMZ Secure Link download"), is installed on a Windows system within the DMZ. 

Publisher Network Diagnostics
-----------------------------

A full diagnostics script to use to report on most network and Publisher-related configuration information which:

1. Displays network configuration information
1. Displays configuration settings for AVEVA Publishers and DMZ Secure Link
1. Reports the results of various communications tests to help pinpoint the cause of problems
1. Where feasible, includes interpretation of the cause and offers recommendations
1. Is a succinct way to describe communication problems when working with Technical Support and IT

Example output from running this script on the Publisher node and on the DMZ Secure Link node are also included.

Tutorial
--------
There is also a [brief video tutorial](https://1drv.ms/v/s!AqHkJ_gHT62Qgb4C-z5HrEpHya8zxQ?e=j7AnHM "Watch") describing the architecture and network configuration
