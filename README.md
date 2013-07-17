Brant_Sniffer (bcsniffer)
---
Copyright 2012 - 2013 Brant Chen (xkdcc@163.com), All Rights Reserved 

##SYNOPSIS

This program is working as a network sniffer.

##REQUIREMENTS

Working on Linux platform.

##DESCRIPTION

I wrote this C language program on RedHat 5 OS as my job entry examination for my first full-time job in 2005.
As time goes by, I spare some time to improve it and now it seems better than original :)

##USAGE:        

bcsniffer [Option] ... [Value]...
-       -p --protocol <TCP|UDP|ICMP> 
         specify protocol to catch.
-       -e --interval <Interval> 
         output linked list when finish snatching packages by default.
-       -n --endcount <Endcount> 
         exit when specified how many packages user want. 
         bcsniffer wont't stop by default if without -n.
-       -x --display 
         display the TCP/UDP data in hex and printable characters. 