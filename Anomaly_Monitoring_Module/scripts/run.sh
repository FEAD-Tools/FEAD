#!/bin/bash

# parse
scene="trace"
with_anomaly=false
train=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --scene) scene="$2"; shift ;;
        --with_anomaly) with_anomaly=true ;;
        --train) train=true ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# scene list
scenes=("cadets" "fivedirections" "theia" "trace")


if [[ ! " ${scenes[@]} " =~ " ${scene} " ]]; then
    echo -e "\033[31mThe scene you choose should be one of cadets, fivedirections, theia, trace.\033[0m"
    exit 1
fi

if [[ "$scene" != "opensmtpd" && "$scene" != "log4jEnv" && "$with_anomaly" == true ]]; then
    echo -e "\033[31mOnly in scene \"opensmtpd\" or \"log4jEnv\" can parameter --with_anomaly be used to specify the use of abnormal scores for training and testing.\033[0m"
    exit 1
fi

# timestamp setting
current_time=$(date +"%Y-%m-%d_%H-%M-%S")

mkdir -p ../result/models-$current_time

if [[ "$train" == true ]]; then
    # train and test
    if [[ "$with_anomaly" == true ]]; then
        python train.py --scene "$scene" --with_anomaly
        python test.py --scene "$scene" --with_anomaly
    else
        python train.py --scene "$scene"
        python test.py --scene "$scene"
    fi
else
    # example_model deployment
    rm -rf ../models/*
    if [[ "$scene" == "opensmtpd" || "$scene" == "log4jEnv" ]]; then
        if [[ "$with_anomaly" == true ]]; then
            cp ../example_models/"$scene"/models_with_anomaly/* ../models/
        else
            cp ../example_models/"$scene"/models_no_anomaly/* ../models/
        fi
    else
        cp ../example_models/"$scene"/* ../models/
    fi
    # test and evaluation
    if [[ "$with_anomaly" == true ]]; then
        python test.py --scene "$scene" --with_anomaly
    else
        python test.py --scene "$scene"
    fi
fi

# evaluate
python evaluate.py > result.txt
cat result.txt
# results output
cp ../models/* ../result/models-$current_time
cp result.txt ../result/result-$current_time.txt
