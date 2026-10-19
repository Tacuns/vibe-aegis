import subprocess

def convert(name):
    subprocess.run(["convert", name, "out.png"], check=True)
