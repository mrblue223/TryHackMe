#!/bin/bash

while true; do
  touch test
  ln -sf /home/run/flag test
  rm test
done
