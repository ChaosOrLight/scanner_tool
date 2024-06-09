import subprocess
import uuid

subprocess.Popen('touch ' + str(uuid.uuid1()) + '.txt', shell=True)
