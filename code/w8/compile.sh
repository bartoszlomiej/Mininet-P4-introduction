#!/bin/bash
p4c-bm2-ss --std p4-16 --target bmv2 --arch v1model --p4runtime-files p4info.txt -o ./build/solution.json ./src/digest.p4
#p4c-bm2-ss --std p4-16 --target bmv2 --arch v1model -o ./build/solution.json ./src/registers.p4
