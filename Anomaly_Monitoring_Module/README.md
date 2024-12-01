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

## Locality-based Anomaly Analysis

The training and testing data files are organized in the following directory structure with six subfolders:

### Directory Structure

1. **data/**
 - Contains training and testing data for DARPA-TC (Due to Git file size limitations, the dataset is hosted externally. You can download it from: [Dataset Download Link](https://drive.google.com/file/d/13oWnCt1uPHjF5iIfUeNmNFoNByRl1_Qw/view?usp=sharing))
 - Each scenario includes `train.txt` and `test.txt`

2. **example_models/**
 - Contains ready-to-use example models for both scenarios

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
--scene scene_name    # Specifies the scenario ("cadets", "fivedirections", "theia", or "trace", default: trace)
--train               # Specifies whether to retrain (default: false, uses example models)
```

## Example Commands

```
./run.sh                                        # trace scenario,  using example model
./run.sh --scene trace --with_anomaly --train   # trace scenario,  retraining model
```

## Results

After script execution, trained models and evaluation results are copied to the result folder. The first line of `result.txt` contains four numbers representing the counts of TP, FP, TN, and FN nodes respectively.