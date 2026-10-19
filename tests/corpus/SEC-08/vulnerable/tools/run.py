import subprocess

def convert(name):
    subprocess.run(f"convert {name} out.png", shell=True)
