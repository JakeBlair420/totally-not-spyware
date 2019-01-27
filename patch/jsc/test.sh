#!/bin/bash

for x in 60?.*.*; do
    g++ -o main main.cpp -I. -I$x -D'ENABLE(x)=1' -D'RELEASE_ASSERT_NOT_REACHED()=';
    printf "$x:\t$(./main)\n";
done
