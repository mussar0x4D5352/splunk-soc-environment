# Defensive Security Project

## Table of Contents

* [Project Overview](#project-overview)
* [Monitoring Environment](#monitoring-environment)
* [Third Party Tools](#third-party-tools)
* [Windows Event Logs](#windows-event-logs)
* [Apache Logs](#apache-logs)
* [Attack Analysis](#attack-analysis)
* [Summmary and Mitigation](#summary-and-mitigation)


## Project Overview

This was the third of four project completed during my time at UT Austin's Cybersecurity Bootcamp. The goal of this project was to gain experience with the Splunk Enterprise platform and simulate the process of baselining a network, building alerts and dashboards, detecting anomalies, and responding to potential threats. I collaborated on this project with the following classmates:

- Andy Nguyen
- Colby Mullins
- Cory Haverstrom
- Luke Raines
- Victor Olarine
- Robert Landry

## Monitoring Environment

As SOC analysts for Virtual Space Industries (VSI), our primary responsibility is to monitor and defend our systems and applications against potential cyberattacks. Recently, we received a tip indicating that our competitor, JobeCorp, may launch targeted attacks against our business. To enhance our security measures, we have been assigned the task of utilizing Splunk to proactively detect and respond to any malicious activities.

With the tip regarding JobeCorp's intent to disrupt our business, our focus is on monitoring indicators of compromise, network traffic, and any unauthorized access attempts across our infrastructure. Through continuous monitoring and analysis of events and logs, we can uncover patterns and anomalies that may indicate an ongoing attack. By promptly investigating and responding to these threats, we can minimize the impact on our operations and protect our sensitive information from falling into the wrong hands.

We analyzed two sets of logs from our network:

1. Windows Event Logs from our Domain Controller
2. Apache Access Logs from our web server

Analysis was performed by establishing a baseline from known good data, building alerts and dashboards, and detecting anomalous activity that may indicate an attack. We then ingested possible attack logs into Splunk and analyzed the data to determine the scope of the attack, efficacy of our alerts, and potential mitigation strategies.

All alert thresholds were set using a statistical analysis of baseline data. The thresholds were set to 1 standard deviation above the mean, which should minimize the risk for false negatives while also reducing the number of false positives.

## Third Party Tools

As part of our project, we incorporated the third party Splunk Add-on WHOIS XML IP Geolocation API. This add-on allows us to enrich our data with geolocation information, which can be used to identify the source of an attack. The add-on can be downloaded from the [Splunkbase website](https://splunkbase.splunk.com/app/5299).

The Geolocation API provides a few additional benefits beyond the default geolocation tools in Splunk. At its core, the API functions similarly to a combination of the iplocation and geostats query commands. However, the API also provides info such as Time Zone conversion, Proxy/VPN Detection, and DNS/ISP lookup. It can be used as a standalone interfact for single IP lookup, or within a query using the `wxageoip` command.

Some scenarios we came up with that would benefit from the Geolocation API include:

* Unusual IP Identification
* Identifying/Blocking Known Proxy/VPN IP ranges
* Reporting "Nuisance" IP addresses to ISP
* Network Performance Analysis
* Threat Intelligence & Incident Response

### Images

## Windows Event Logs

### Reports

* Windows Server Logs | Signature X ID - A table view of every signature field, with its corresponding signature ID.
* Windows Server Logs | Severity Count - A detailed look at the individual fields for severity level, with a pie graph showing the count of each severity level.
* Windows Server Logs | Status Count - A chart view of the indivudal fields related to Status, showing the counts for failures and successes.
* Windows Server Logs | User Activity Count - A line char view showcasting the count of activities for all users.

### Report Images

### Alerts

* Increase of Failed Windows Alerts - This alert triggers during failed password reset attempts. Our alert baseline averaged around 9 reset attempts per hour, and our alert threshold was set to 12.
* Unusually High Number of Logins - This alert triggers when the number of successful logins exceeds the baseline of 20 per hour. The threshold was set to 24.
* Unusual Number of Account Deletions - This alert triggers when the account cleanup process exceeds the baseline of 33 per hour. The threshold was set to 40.

### Alert Images

## Apache Logs

### Reports

* Apache HTTP Response Codes - This returns the count of HTTP Methods and identifies the specific response codes.
* Apache Top 10 Referrer Domains - This returns the 10 most common referrer domains.
* Apache International Activity - This returns all IP addresses located outside the United States.
* Apache HTTP Methods - This returns the count of individual status codes for each HTTP Method.

### Report Images

### Alerts

* Non-US IP Alert - This alert triggers when an IP address outside the United States is detected. The baseline was set to 75, and the threshold was set to 150.
* High Hourly POST Requests - This alert triggers when the number of POST requests exceeds the baseline of 1.5 per hour. The threshold was set to 4.

### Alert Images

## Attack Analysis

### Attack Summary - Windows:

* The severity field 'high' alert showed a suspicious increase from approximately 6.9% to 20.2%, indicating a uptick on malicious activity.
* Failed activities in the Status field experienced a decrease from around 3% to 1.5%, which could suggest a decrease in unsuccessful malicious attempts. 
* The time chart of signatures revealed notable spikes, particularly for the signatures "A User Account was Locked Out" and "An attempt was made to reset an account password."
* Users dashboard displayed spikes in activity for User A, User K, and a smaller spike for User J.
* An increased volume of failed activity was detected, with a count of 35 events occurring at 8am on Wednesday, March 25, 2020. The alert threshold for this activity was set at 12, which proved effective in triggering the alert.
* An increased volume of successful logins was detected, with a count of 196 successful logon events. The threshold for this alert was set at 20, and it would have been triggered.
Overall the team concludes, the chosen thresholds for these alerts have proven to be appropriate. 
* The Time Chart of Signatures displayed suspicious spikes, particularly for the signatures "A User Account was Locked Out" and "An attempt was made to reset an account password." These spikes occurred at different time intervals, with the former happening from 12:00am to 3:00am with a peak count of 896  and the latter from 8:00am to 11:00am on March 25, 2020 with a peak count of 1258. 
* The Users dashboard revealed spikes in activity for User A and User K, aligning with the findings in the time chart. These findings reinforce the presence of suspicious activities during the attack.

### Attack Log Images

### Attack Summary - Apache:

* The Methods report showed an overall lower number of total requests, but the percentage of POST requests was significantly higher. The events from referrer domains also significantly dropped in the attack logs, and http://tuxradar.com appeared in the top 10 results from the attack logs. After examining the alert logs for the HTTP response codes, the number of 404 GET requests and 200 POST requests have spiked. This leads us to believe that an attacker is attempting an attack on our servers and getting many failed results.
* The HTTP POST alert triggered showing an increase in the amount of POST requests. We had a low threshold of 4 per hour, based on our normal activity, which was greatly exceeded during the attack, where 1296 events occurred during the hour. Similarly, our non-US IP address alert spiked at the time of the attack. We set a threshold of 146 per hour. during the attack, 939 events happened between 8-9PM on March 25, 2020.
* Based on the analysis, we have found an unusual spike in HTTP POST requests around 8 PM on March 25, 2020. There was a higher amount of activity from IP addresses in Kiev, Ukraine. /VSI_Account_logon.php was hit the most during this time. This evidence suggests we are under some sort of attack, such as a brute force attack or SQL injection attempts at our /VSI_Account_logon.php URI originating from Kiev, Ukraine.

### Attack Log Images

## Summary and Mitigation

The findings are consistent with brute force attacks on user logins, resulting in successful logins from unauthorized users. Based on the available evidence, it is likely that attackers residing in or tunneling through Kiev, Ukraine gained unauthorized access to user accounts.

The team recommends the following mitigation strategies:

* Implement Multi-Factor Authentication (MFA) for all accounts.
* Require FIDO2 security keys for all administrator accounts.
* Perform a full audit of all user accounts and account passwords.