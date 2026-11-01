"""Run an explicitly supplied server-side Python maintenance script over pinned SSH."""
import pathlib,sys
sys.path.insert(0,r'C:\Users\YOUR_USER\Documents\Codex\2026-10-25\ni\work')
from provision import ssh
if __name__=='__main__':
    print(ssh('sudo -n python3 -',pathlib.Path(sys.argv[1]).read_bytes()).decode('utf-8','replace'))
