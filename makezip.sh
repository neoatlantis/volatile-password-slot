#!/bin/sh

if [ -r $1.zip ]; then
    rm $1.zip
fi

zip -r $1.zip  $1.js   volatile-passwords
