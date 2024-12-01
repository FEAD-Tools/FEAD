#!/bin/bash

# 参数解析
scene="opensmtpd"
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

# 场景列表
scenes=("opensmtpd" "log4jEnv")

# 检查参数合法性
if [[ ! " ${scenes[@]} " =~ " ${scene} " ]]; then
    echo -e "\033[31mThe scene you choose should be one of opensmtpd, log4jEnv.\033[0m"
    exit 1
fi

if [[ "$scene" != "opensmtpd" && "$scene" != "log4jEnv" && "$with_anomaly" == true ]]; then
    echo -e "\033[31mOnly in scene \"opensmtpd\" or \"log4jEnv\" can parameter --with_anomaly be used to specify the use of abnormal scores for training and testing.\033[0m"
    exit 1
fi

# 设置时间戳
current_time=$(date +"%Y-%m-%d_%H-%M-%S")
# 创建结果目录
mkdir -p ../result/models-$current_time

if [[ "$train" == true ]]; then
    # 进行训练、测试和评估
    if [[ "$with_anomaly" == true ]]; then
        python train.py --scene "$scene" --with_anomaly
        python test.py --scene "$scene" --with_anomaly
    else
        python train.py --scene "$scene"
        python test.py --scene "$scene"
    fi
else
    # 复制示例模型文件到models目录
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
    # 直接进行测试和评估
    if [[ "$with_anomaly" == true ]]; then
        python test.py --scene "$scene" --with_anomaly
    else
        python test.py --scene "$scene"
    fi
fi

# 运行evaluate.py并保存结果
python evaluate.py > result.txt
cat result.txt
# 将文件复制到结果目录
cp ../models/* ../result/models-$current_time
cp result.txt ../result/result-$current_time.txt