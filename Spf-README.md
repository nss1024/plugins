SPF plugnin

A Java implementation of the Sender Policy Framework (SPF) evaluation algorithm based on RFC 7208.

This project implements SPF record parsing and evaluation from scratch, including DNS resolution, mechanism processing, and lookup limits defined in the RFC.

The goal of the project was to better understand how email authentication actually works internally by implementing the protocol directly from its specification.

Features

SPF record parsing

Support for major SPF mechanisms

IPv4 and IPv6 CIDR matching

DNS lookup tracking (RFC limit: 10)

Recursive evaluation (include)

Redirect support

PTR validation

Command-pattern architecture for mechanisms

Designed as a security plugin module

Supported SPF Mechanisms
Mechanism	Supported
a	
aaaa	
mx	
ip4	
ip6	
exists	
include	
ptr	
all	
redirect
Architecture

The resolver evaluates SPF records using a queue-based evaluation engine and a command pattern for SPF mechanisms.

Purpose

This project is part of a broader effort to implement networking protocols directly from RFC specifications in order to gain deeper understanding of internet infrastructure.



This project is part of a broader effort to implement networking protocols directly from RFC specifications in order to gain deeper understanding of internet infrastructure.
![SpfEvaluation](https://github.com/user-attachments/assets/78868d66-760f-4fd2-b227-071ec7395d8f)



