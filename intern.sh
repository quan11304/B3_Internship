#!/bin/bash

cd $HOME/Git/b3_intern/3
xed *.asm &
xed --new-window ../2/*.c ref/macros64.inc test.c &
xed --new-window *.inc ../README.md &
gnome-terminal . &
disown -r
