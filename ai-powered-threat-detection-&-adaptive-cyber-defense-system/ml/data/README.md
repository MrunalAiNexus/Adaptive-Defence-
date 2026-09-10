# NSL-KDD Cybersecurity Benchmark Dataset

## 1. Overview and Rationale
For this Honours Computer Science project, **NSL-KDD** was selected as the primary benchmark dataset. 

### Why NSL-KDD?
1. **Solves KDD Cup 99 Deficiencies**: The original KDD'99 dataset suffered from massive redundancy (78% duplicate records in train and 75% in test), which artificially skewed machine-learning classifier accuracy. NSL-KDD solved this by removing duplicate records and calibrating difficulty levels.
2. **Standardized Reproducibility**: NSL-KDD remains one of the most widely benchmarked datasets in network intrusion detection literature, allowing direct academic comparison with published state-of-the-art papers.
3. **Diverse Threat Class Distribution**: Encompasses four major attack taxonomy families:
   - **DoS (Denial of Service)**: e.g. Neptune, Smurf, Pod, Teardrop.
   - **Probe (Reconnaissance / Port Scanning)**: e.g. Portsweep, Nmap, Ipsweep, Satan.
   - **R2L (Remote to Local / Brute Force)**: e.g. Guess_Passwd, Ftp_write, Imap.
   - **U2R (User to Root / Bot / Buffer Overflow)**: e.g. Buffer_overflow, Rootkit, Loadmodule.
4. **Computational Feasibility**: Full training set (`KDDTrain+.txt`) has 125,973 instances and the test set (`KDDTest+.txt`) has 22,544 instances, which trains in under 30 seconds on a modern student laptop without needing high-performance GPU clusters.

## 2. Dataset Licensing and Access Instructions
In accordance with academic integrity and ethical data redistribution guidelines, raw benchmark datasets are retrieved directly from official university repositories:
- University of New Brunswick (UNB) Canadian Institute for Cybersecurity:
  `https://www.unb.ca/cic/datasets/nsl.html`

### Download Instructions
To download the canonical files manually into this directory:
```bash
# 1. Download KDDTrain+.txt
curl -o ml/data/KDDTrain+.txt https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt

# 2. Download KDDTest+.txt
curl -o ml/data/KDDTest+.txt https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt
```

A sample test file with canonical columns is provided in `ml/data/sample_nsl_kdd.csv` for zero-configuration local execution and API testing.
