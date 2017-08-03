import subprocess
from yunohost.tools import Migration


class MyMigration(Migration):
    "Remove archivemount because we don't use it anymore"

    def forward(self):
        subprocess.check_call("apt-get remove archivemount -y", shell=True)

    def backward(self):
        subprocess.check_call("apt-get install archivemount -y", shell=True)
