#!/bin/sh

# Проверка существования директории
if [ -e /usr/local/share/ca-certificates/extra/ ]; then 
	echo "Folder already exists"
else
	mkdir /usr/local/share/ca-certificates/extra
fi

# Перевод .cer файлов в .pem
cd /app/Infra/Ca_Certs
for f in *.cer; do
    if [ -f "$f" ]; then
        openssl x509 -inform der -in "$f" -out "${f%.cer}.pem"
    fi
done

# Копирование .pem файлов в /etc/ssl/certs/
cp -a /app/Infra/Ca_Certs/*.pem /etc/ssl/certs/

# Переименование .pem в .crt
for f in *.pem; do 
    mv -- "$f" "${f%.pem}.crt"
done

# Копирование .crt файлов в /usr/local/share/ca-certificates/extra/
cp -a /app/Infra/Ca_Certs/*.crt /usr/local/share/ca-certificates/extra/

# Обновление сертификатов
update-ca-certificates

# Переименование .crt обратно в .pem
for f in *.crt; do 
    mv -- "$f" "${f%.crt}.pem"
done
