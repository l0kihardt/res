#/bin/sh -e
# commands to execute when you are building a new vps

sudo apt update
sudo apt install -y tmux gcc git zsh wget curl docker.io vim bc cmake 
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
mkdir .ssh
pushd .ssh
echo "" >> authorized_keys
popd
sed -i 's/Port 22/Port 20037/g' /etc/ssh/sshd_config
service ssh restart
