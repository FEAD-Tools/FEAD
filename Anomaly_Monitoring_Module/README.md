# 1. Testing and Evaluation

## Environment Setup

Our training and testing environment is configured as follows:
- `Python 3.8.10`
- Key dependencies:
`torch                  1.4.0+cpu`
`torch-cluster          1.5.4`
`torch-geometric        1.4.3`
`torch-scatter          2.0.4`
`torch-sparse           0.6.1`
`torch-spline-conv      1.2.0`
`torchvision            0.5.0+cpu`
Other packages can be installed according to dependency requirements.

## Edge Monitoring

First, edge monitoring is performed. By executing `score.py`, preliminary monitoring of edge-side data is conducted using predefined detection rules (refer to the "Monitor Detection Rules Documentation" deliverable). This generates the `nodes_with_encode_reduce_index_deldup_anomaly.csv` file.

## Global Traceability Analysis

The training and testing data files are organized in the following directory structure with six subfolders:

### Directory Structure

1. **data/**
 - Contains training and testing data for two scenarios: opensmtpd and log4jEnv
 - Each scenario includes `train.txt` and `test.txt`
 - Also contains `nodes_with_encode_reduce_index_deldup_anomaly_benign.csv` and `nodes_with_encode_reduce_index_deldup_anomaly_malicious.csv` for training and testing with anomaly scores

2. **example_models/**
 - Contains ready-to-use example models for both scenarios
 - Models are organized in `models_no_anomaly` and `models_with_anomaly` based on whether anomaly scores are used

3. **groundtruth/**
 - Contains true anomaly node information for both scenarios

4. **models/**
 - Stores models and temporary files generated during training

5. **result/**
 - Stores final trained models and evaluation results

6. **scripts/**
 - Contains Python code and bash scripts for data processing, training, testing, and evaluation

## Running Tests

The `run.sh` script in the scripts folder provides one-click completion of training, testing, and evaluation operations. It accepts three optional parameters:

```bash
--scene scene_name    # Specifies the scenario (opensmtpd or log4jEnv, default: opensmtpd)
--with_anomaly       # Specifies whether to use anomaly scores (default: false)
--train             # Specifies whether to retrain (default: false, uses example models)
```

## Example Commands

```
./run.sh                                           # opensmtpd scenario, no anomaly scores, using example model
./run.sh --with_anomaly --scene opensmtpd          # opensmtpd scenario, with anomaly scores, using example model
./run.sh --scene log4jEnv --with_anomaly --train   # log4jEnv scenario, with anomaly scores, retraining model
```

## Results

After script execution, trained models and evaluation results are copied to the result folder. The first line of `result.txt` contains four numbers representing the counts of TP, FP, TN, and FN nodes respectively.