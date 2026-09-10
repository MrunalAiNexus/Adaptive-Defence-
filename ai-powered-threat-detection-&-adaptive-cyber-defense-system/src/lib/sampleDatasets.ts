/**
 * Sample datasets and pre-packaged telemetry vectors for testing and demonstration.
 * Generated from authentic NSL-KDD feature distributions.
 */

import { NetworkTelemetry } from '../types';

export const SAMPLE_ATTACK_SCENARIOS: { name: string; description: string; telemetry: NetworkTelemetry }[] = [
  {
    name: 'SYN Flood Denial of Service (DoS)',
    description: 'High volumetric burst of half-open TCP SYN packets (S0) aimed at overwhelming server socket queues.',
    telemetry: {
      timestamp: new Date().toISOString(),
      sourceIp: '198.51.100.44',
      destinationIp: '10.0.2.15',
      sourcePort: 49152,
      destinationPort: 80,
      protocol: 'TCP',
      duration: 0.2,
      srcBytes: 120,
      dstBytes: 0,
      packetCount: 540,
      failedLoginAttempts: 0,
      requestFrequency: 450,
      connectionState: 'S0',
      service: 'http',
      sameSrvRate: 1.0,
      diffSrvRate: 0.0,
      dstHostCount: 255,
      dstHostSrvCount: 255,
    },
  },
  {
    name: 'SSH Distributed Brute Force (R2L)',
    description: 'Repeated authentication failures against port 22 with dictionary password spraying.',
    telemetry: {
      timestamp: new Date().toISOString(),
      sourceIp: '203.0.113.89',
      destinationIp: '10.0.2.22',
      sourcePort: 55412,
      destinationPort: 22,
      protocol: 'SSH',
      duration: 18.5,
      srcBytes: 1820,
      dstBytes: 420,
      packetCount: 38,
      failedLoginAttempts: 7,
      requestFrequency: 45,
      connectionState: 'SF',
      service: 'ssh',
      sameSrvRate: 0.95,
      diffSrvRate: 0.05,
      dstHostCount: 14,
      dstHostSrvCount: 12,
    },
  },
  {
    name: 'Stealth Nmap PortScan (Probe / Recon)',
    description: 'Horizontal reconnaissance probing multiple ports with high rejection rate to map vulnerable listening daemons.',
    telemetry: {
      timestamp: new Date().toISOString(),
      sourceIp: '192.0.2.110',
      destinationIp: '10.0.2.50',
      sourcePort: 60124,
      destinationPort: 445,
      protocol: 'TCP',
      duration: 2.1,
      srcBytes: 64,
      dstBytes: 0,
      packetCount: 88,
      failedLoginAttempts: 0,
      requestFrequency: 120,
      connectionState: 'REJ',
      service: 'other',
      sameSrvRate: 0.12,
      diffSrvRate: 0.88,
      dstHostCount: 240,
      dstHostSrvCount: 4,
    },
  },
  {
    name: 'Web Application SQL Injection (Web Attack)',
    description: 'Anomalous HTTP payload containing SQL metadata fragments causing unexpected backend response error codes.',
    telemetry: {
      timestamp: new Date().toISOString(),
      sourceIp: '185.220.101.5',
      destinationIp: '10.0.2.10',
      sourcePort: 44102,
      destinationPort: 443,
      protocol: 'HTTP',
      duration: 4.8,
      srcBytes: 14200,
      dstBytes: 850,
      packetCount: 45,
      failedLoginAttempts: 0,
      requestFrequency: 65,
      connectionState: 'SF',
      service: 'http',
      sameSrvRate: 0.8,
      diffSrvRate: 0.2,
      dstHostCount: 45,
      dstHostSrvCount: 40,
    },
  },
  {
    name: 'Legitimate Authorized HTTPS Browsing (Benign)',
    description: 'Normal employee web browsing session with graceful connection close and zero authentication anomalies.',
    telemetry: {
      timestamp: new Date().toISOString(),
      sourceIp: '10.0.1.105',
      destinationIp: '142.250.190.46',
      sourcePort: 52100,
      destinationPort: 443,
      protocol: 'TCP',
      duration: 14.2,
      srcBytes: 2450,
      dstBytes: 18400,
      packetCount: 28,
      failedLoginAttempts: 0,
      requestFrequency: 4.2,
      connectionState: 'SF',
      service: 'http',
      sameSrvRate: 1.0,
      diffSrvRate: 0.0,
      dstHostCount: 8,
      dstHostSrvCount: 8,
    },
  },
];

export const SAMPLE_CSV_CONTENT = `sourceIp,destinationIp,sourcePort,destinationPort,protocol,duration,srcBytes,dstBytes,packetCount,failedLoginAttempts,requestFrequency,connectionState,service,sameSrvRate,diffSrvRate,dstHostCount,dstHostSrvCount
198.51.100.44,10.0.2.15,49152,80,TCP,0.2,120,0,540,0,450,S0,http,1.0,0.0,255,255
203.0.113.89,10.0.2.22,55412,22,SSH,18.5,1820,420,38,7,45,SF,ssh,0.95,0.05,14,12
192.0.2.110,10.0.2.50,60124,445,TCP,2.1,64,0,88,0,120,REJ,other,0.12,0.88,240,4
10.0.1.105,142.250.190.46,52100,443,TCP,14.2,2450,18400,28,0,4.2,SF,http,1.0,0.0,8,8
185.220.101.5,10.0.2.10,44102,443,HTTP,4.8,14200,850,45,0,65,SF,http,0.8,0.2,45,40
198.51.100.77,10.0.2.15,50100,80,TCP,0.1,80,0,420,0,380,S0,http,1.0,0.0,255,255
10.0.1.108,172.217.16.206,53200,53,DNS,0.05,72,128,4,0,1.2,SF,dns,1.0,0.0,4,4
203.0.113.99,10.0.2.22,58100,22,SSH,12.0,1400,310,24,5,30,SF,ssh,0.9,0.1,10,8
192.0.2.115,10.0.2.80,61000,8080,TCP,1.5,40,0,60,0,95,REJ,other,0.05,0.95,210,2
10.0.1.112,10.0.2.5,48200,443,TCP,22.4,4100,32000,52,0,5.8,SF,http,1.0,0.0,12,12`;
