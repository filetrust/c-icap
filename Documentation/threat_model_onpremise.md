# On-Premise Threat Model

This model examines the controls and defenses needed to enable the secure running of the Glasswall ICAP service deployed within a customer network.

## Data-flow Diagram

!image[On-premise Data-flow Diagram](img/on-premise-deployment.png)


## Facts

These are immutable assumptions under which the threat modelling is undertaken.

ID  | Description 
:---|:------------
F01 | Assume the internal customer network is secure.
F02 | Assume that the ICAP Server does not handle a malicious ICAP Client.
F03 | Assume that at no point in the processing of a file is it 'opened' thus triggering any malicious content.


##  Security Controls

ID  | Description 
:---|:------------
C01 | GW Engine Run in Docker Container to limit Blast Radius
C02 | Network security Controls
C03 | Kubernetes Cluster
C04 | Functional Testing with Abuse Cases

## Assets

ID  | Description 
:---|:------------
A01 | ICAP Server

## Threat Actor

ID   | Description 
:----|:------------
TA01 |

# Threat Register
Component | Threat | Threat Actor | Vulnerability | Risk | Risk Possibility | Risk Impact | Risk Level | Security Control 
:---------|:-------|:-------------|:--------------|:-----|:-----------------|:------------|:-----------|:----------------
ICAP Client - ICAP Server | Session hijacking/ MITM | Attacker to internal network | No encryption | External Attacker executing a MITM | Very Unlikely | Significant | Medium | Accept 
Rebuild API | Remote code execution from malicious file | User Accidental/malicious attacker | 0-day vulnerability | File enabling remote code execution | Unlikely | Severe | Medium Hi | SC01
ICAP Client - ICAP Server | Tampering |Malicious insider or customer with access to internal network | No signing ability/validation | Input/Output Tampered | Possible | Minor | Low Med | Accept
ICAP Client - ICAP Server | Data leak |Internal Ineffective/Accidental | No encryption | Reputational damage, unplanned costs due to data leak | Very Unlikely | Significant | Medium | Present To Customer (01)
Internal Network |  Information disclosure after a soft delete |  Malicious File | Transferring malicious files | Information disclosure after a soft delete | Very Unlikely | Severe | Low Medium | Accept
User - ICAP server (HTTPS) | Session hijacking/MITM/spoofing |External Attacker/Rogue user | Vulnerable if old versions used | Unplanned costs, Reputational damage | Unlikely | Minor | Low Med | Out of Scope (02)
ICAP Server | Malicious file |Advanced attacker | Buffer Overflow Vulnerability | Unplanned costs due to GW Engine repair after buffer overflow attack | Unlikely | Severe | Medium Hi | SC02, SC03, SC04
ICAP Server | Malicious file |Advanced attacker | DoD Vulnerability | Unplanned costs due to GW Engine Repair, Reputational Damage, Customer Loss | Unlikely | Severe | Medium Hi | SC02, SC03, SC04

(01) Present to customer and the customer decides on risk
(02) Out of scope - assumption that F5 network is safe (F01)
