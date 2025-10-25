#!/bin/bash

for i in {1..50}
do
    echo "=== Run $i ==="
    make grade > grade.log 2>&1
    # 检查满分关键字
    if ! grep -q "Score: 80/80" grade.log; then
        echo "Run $i: Not full score!" >> fail.log
        echo "----------------------" >> fail.log
        cat grade.log >> fail.log
        echo "----------------------" >> fail.log
    fi
done

echo "Done. Check fail.log for details."