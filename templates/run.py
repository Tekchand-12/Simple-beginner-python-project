import os

print os.popen("apt-get autoremove genome-terminal",'rb').read()