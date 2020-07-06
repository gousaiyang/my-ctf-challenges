#!/bin/bash
while true; do
    docker-compose down -v
    docker-compose up --build -d
    sleep 120
done
