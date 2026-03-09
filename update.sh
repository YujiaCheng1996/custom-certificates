#!/bin/bash

case version in
*-*)
    ;;
*)
    git checkout -B master origin/master
    cat module/module.prop | (
    IFS="="
    while read k v; do
        read $k <<< "$v"
    done
    cat << EOF > update.json
{
  "version": "$version",
  "versionCode": $versionCode,
  "zipUrl": "https://github.com/YujiaCheng1996/custom-certificates/releases/download/$version/custom-certificates-$version.zip",
  "changelog": "https://github.com/YujiaCheng1996/custom-certificates/releases/tag/$version"
}
EOF
    )
    git add update.json
    git commit -m "skipci: Update update.json" || true
    ;;
esac
