# Focus-Enhanced Attack Detection (FEAD): Leveraging Security-Oriented Efficient Monitoring and Localized Anomaly Analysis
## Abstract

Traditional security detection methods struggle to keep pace with the rapidly evolving landscape of cyber threats targeting critical infrastructure and sensitive data. These approaches suffer from three critical limitations: non-security-oriented system activity data collection that fails to capture crucial security events, growing security monitoring demands that lead to continuously expanding monitoring systems, thereby causing excessive resource consumption, and inadequate detection algorithms that result in the inability to accurately distinguish between malicious and benign activities, resulting in high false positive rates.

To address these challenges, we present FEAD (Focus-Enhanced Attack Detection), an attack detection framework that improves detection by focusing on identifying and supplementing security-critical monitoring items and deploying them efficiently during data collection, as well as the locality of potential anomalous entities and their surrounding neighbors during anomaly analysis. FEAD incorporates three key innovations:

(1) an attack model-driven approach that extracts security-critical monitoring items from online attack reports, enabling a more comprehensive monitoring items framework; (2) an efficient task decomposition mechanism that optimally distributes monitoring tasks across existing collectors, maximizing the utilization of available monitoring resources while minimizing additional monitoring overhead; (3) a locality-aware anomaly analysis technique that exploits the characteristic of malicious activities forming dense clusters in provenance graphs during active attack phases, guiding a vertex-level weight mechanism in our detection algorithm to better distinguish between anomalous and benign vertices, thereby improving detection accuracy and reducing false positives.

Evaluations show FEAD outperforms existing solutions with an 8.23% higher F1-score and 5.4% overhead. Our ablation study also confirms that FEAD’s focus-based designs significantly boost detection performance.

## Overview

This repository implements a system for monitoring and detecting anomalies in environment variables. It is organized into two main components:

### Data Collection and Parse Module
The [Data_Collection_And_Parse](./Data_Collection_And_Parse) module is responsible for:
- Collecting system events as logs for provenance tracking
- Processing and parsing the collected data
- Providing running examples of the monitoring process (environment variable data)
- Implementing data preprocessing pipelines
- Constructing provenance graphs from parsed events

### Anomaly Monitoring Module
The [Anomaly_Monitoring_Module](./Anomaly_Monitoring_Module) contains:
- Implementation of locality-based anomaly detection algorithms
- Core logic for identifying and analyzing anomalies
- Processing mechanisms for the collected log/data

