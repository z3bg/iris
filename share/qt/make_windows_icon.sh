#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/identifi.png
ICON_DST=../../src/qt/res/icons/identifi.ico
convert ${ICON_SRC} -resize 16x16 identifi-16.png
convert ${ICON_SRC} -resize 32x32 identifi-32.png
convert ${ICON_SRC} -resize 48x48 identifi-48.png
convert identifi-16.png identifi-32.png identifi-48.png ${ICON_DST}

