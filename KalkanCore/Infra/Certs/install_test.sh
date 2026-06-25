#!/bin/bash

if [ -e /usr/local/share/ca-certificates/extra/ ]; 
then 
	echo "Folder already exists"
else
	mkdir /usr/local/share/ca-certificates/extra
fi

cp -a /app/Infra/Certs/Pems/*.pem /etc/ssl/certs/

cd /app/Infra/Certs/Pems
for f in *.pem; do 
    mv -- "$f" "${f%.pem}.crt"
done

cp -a /app/Infra/Certs/Pems/*.crt /usr/local/share/ca-certificates/extra/

update-ca-certificates

for f in *.crt; do 
    mv -- "$f" "${f%.crt}.pem"
done
