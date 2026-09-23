# Run on Linux after building internal/session tests with go test -c.
# Usage: python3 scripts/tests/credential-navigation.py /path/to/session.test
import os, pty, select, time, signal, re, sys

helper = os.path.abspath(sys.argv[1])

def run(keys):
 pid, fd=pty.fork()
 if pid==0:
  os.environ.update(TERM='xterm-256color', GUACDEPLOY_CREDENTIAL_NAV_TEST='1', NO_COLOR='1')
  os.execv(helper,['session-nav.test','-test.run=^TestCredentialNavigationPTYHelper$'])
 data=b''
 def read(seconds):
  nonlocal data
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   if select.select([fd],[],[],0.05)[0]:
    try:data+=os.read(fd,65536)
    except OSError:break
 read(.5)
 for key in keys:
  os.write(fd,key)
  read(.4)
 try:os.kill(pid,signal.SIGKILL)
 except ProcessLookupError:pass
 os.waitpid(pid,0); os.close(fd)
 return data.decode(errors='replace')

failures=[]
for key,mode in [(b't','tpm'),(b'h','host'),(b'e','env'),(b'p','prompt')]:
 text=run([key])
 if 'CREDENTIAL_SELECTION_FINISHED:'+mode not in text:failures.append(mode+': selecting once did not finish')
text=run([b'b'])
frames=text.split('\x1b[H')
last=frames[-1]
headers=re.findall(r'\x1b\[5;1H\x1b\[2K([^\x1b\r\n]*)', text)
if not headers or '01  Check this host' not in headers[-1]:failures.append('Back: still shows the wrong current task')
if 'Check this host' not in last:failures.append('Back: host task not visible')
text=run([b'b',b'c',b'h'])
if 'CREDENTIAL_SELECTION_FINISHED:host' not in text:failures.append('Forward: did not return to protection and accept Host key')
text=run([b'f',b'y'])
if 'CREDENTIAL_SELECTION_FINISHED:file' not in text:failures.append('Plaintext approval did not finish')
for f in failures:print('FAIL:',f)
if not failures:print('PASS: single selection and Back task heading')
raise SystemExit(bool(failures))
