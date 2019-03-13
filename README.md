# binaryninja-radare2

This plugin allows Binary Ninja to take advantage of radare2's linear sweep,
function name matching and transfering radare2 comments.


## Linux Installation

```bash
sudo pip install r2pipe
cd ~/.binaryninja/plugins 
git clone https://github.com/Manouchehri/binaryninja-radare2 binaryninja_radare2
echo "import binaryninja_radare2" >> ~/.binaryninja/plugins/wrapper.py
```

## macOS Installation

Note: You probably need to run [binja-fixer](https://github.com/Manouchehri/binja-fixer) so that Binary Ninja will use the same Python library as r2pipe.

```bash
brew install radare2
pip2 install r2pipe
```

```bash
cd /Users/$USER/Library/Application\ Support/Binary\ Ninja/plugins/
 git clone https://github.com/Manouchehri/binaryninja-radare2 binaryninja_radare2
echo "import binaryninja_radare2" > wrapper.py
```
