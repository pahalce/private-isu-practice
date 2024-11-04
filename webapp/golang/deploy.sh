#!/bin/sh

set -v
now=$(date +%Y%m%d-%H%M%S)
branch=main

sudo mkdir -p log

if [ -f /var/log/nginx/access.log ]; then
    if [ -s /var/log/nginx/access.log ]; then
        # mysqlを単体で実行した場合にslow.logの方にだけlogが残る。それをpt-query-digestしたくはないのでここからslow.logが空かどうかの分岐に入る
        # access.logが空でslow.logが空でない場合はないと想定
        if [ -f /var/log/mysql/slow.log ]; then
            if [ -s /var/log/mysql/slow.log ]; then
                # access.logを見やすく吐き出して退避
                sudo cat /var/log/nginx/access.log | alp ltsv -o count,2xx,3xx,4xx,5xx,method,uri,avg,sum,p90,p95,p99 -m '/posts/*,/image/*.*,/@.+' --sort sum -r > log/alp-ltsv.${now}.log
                sudo rm -f log/alp-ltsv.log
                sudo ln -s alp-ltsv.${now}.log log/alp-ltsv.log
                sudo mv -v /var/log/nginx/access.log /var/log/nginx/access.log.${now}
                # slow.logを見やすく吐き出して退避
                sudo mysqldumpslow /var/log/mysql/slow.log > log/mysqldumpslow.${now}.log
                sudo pt-query-digest /var/log/mysql/slow.log > log/pt-query-digest.${now}.log
                sudo rm -f log/mysqldumpslow.log log/pt-query-digest.log
                sudo ln -s mysqldumpslow.${now}.log log/mysqldumpslow.log
                sudo ln -s pt-query-digest.${now}.log log/pt-query-digest.log
                sudo mv -v /var/log/mysql/slow.log /var/log/mysql/slow.log.${now}
                # my-go-app.logを見やすく吐き出して退避
                sudo mv -v /home/isucon/private_isu/webapp/golang/log/my-go-app.log /home/isucon/private_isu/webapp/golang/log/my-go-app.log.${now}
                sudo touch /home/isucon/private_isu/webapp/golang/log/my-go-app.log
                sudo chmod 777 /home/isucon/private_isu/webapp/golang/log/my-go-app.log
            else
            # mysqlを単体で実行してslow.logの方にだけlogが残っている場合はslow.log削除
                sudo mv -v /var/log/mysql/slow.log /var/log/mysql/slow.log.${now}
            fi
        fi     
    fi
fi

sudo systemctl restart mysql
cd /home/isucon/private_isu/webapp
sudo git pull origin main
cd golang
make
sudo systemctl restart isu-go.service
sudo mysqladmin -uroot -proot flush-logs
sudo systemctl reload nginx