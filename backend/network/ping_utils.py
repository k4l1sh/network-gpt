import subprocess

def ping_host(host, count=4):
    try:
        output = subprocess.check_output(['ping', '-c', str(count), host], stderr=subprocess.STDOUT, universal_newlines=True)
        results = output
    except subprocess.CalledProcessError as e:
        results = str(e.output)
    return results.replace("\n", "<br/>")