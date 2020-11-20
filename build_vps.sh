#/bin/sh -e
# commands to execute when you are building a new vps

sudo apt update
sudo apt install -y tmux gcc git zsh wget curl docker.io vim
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
