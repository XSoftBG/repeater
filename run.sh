#!/bin/bash

cd /var/cache/repeater/

while true
do
  sleep 3
  if [ ! -f stop ] 
  then
    ./repeater/repeater -loglevel DEBUG -dump /var/www/repeater/repeater.js >>./repeater.log 2>&1
  fi
  sleep 3
done

