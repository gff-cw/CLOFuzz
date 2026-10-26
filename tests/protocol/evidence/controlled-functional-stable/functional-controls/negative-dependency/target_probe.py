import os, pathlib, sys
pathlib.Path(sys.argv[1]).write_text('started')
os.execv(sys.argv[2], [sys.argv[2], '123'])
