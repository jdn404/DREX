#!/bin/bash
pkg update -y && pkg upgrade -y
pkg install golang git -y
git clone https://github.com/jdn404/DREX.git
cd DREX
go mod tidy
go build -o drex .
echo ""
echo "Build complete. Run: ./drex scan econet"
