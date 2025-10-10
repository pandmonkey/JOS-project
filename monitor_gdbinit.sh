#!/bin/bash

# 监控目录路径
WATCH_DIR="/home/srz/pku_class/jos/lab"

# 无限循环监控
while true; do
    # 检查 .gdbinit 是否存在
    if [ -f "$WATCH_DIR/.gdbinit" ]; then
        echo "Detected .gdbinit, deleting..."
        rm "$WATCH_DIR/.gdbinit"
    fi
    # 每隔 1 秒检查一次
    sleep 1
done