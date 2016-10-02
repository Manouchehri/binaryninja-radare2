# binaryninja-radare2

This plugin allows Binary Ninja to take advantage of radare2's linear sweep (which Binja currently does not offer).

Usually this will identify several functions that were missed by Binja.

# Installation

```
sudo pip install r2pipe
cd ~/.binaryninja/plugins 
git clone https://github.com/Manouchehri/binaryninja-radare2 binaryninja_radare2
echo "import binaryninja_radare2" >> ~/.binaryninja/plugins/wrapper.py
```
