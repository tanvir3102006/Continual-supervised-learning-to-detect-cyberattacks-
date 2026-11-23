#!/bin/sh
mkdir -p out && javac -d out src/ids/*.java && java -cp out ids.Main "${1:-8080}"
