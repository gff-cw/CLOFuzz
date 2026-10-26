import socket, subprocess, threading, json, time
from pathlib import Path
root=Path(__file__).resolve().parent
records=[]
ready=threading.Event()
def proxy():
 with socket.socket() as listener:
  listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  listener.bind(('127.0.0.1',18103)); listener.listen(); ready.set()
  with listener.accept()[0] as client, socket.create_connection(('127.0.0.1',18102)) as server:
   def relay(src,dst,direction):
    pending=b''
    try:
     while True:
      b=src.recv(65536)
      if not b:break
      dst.sendall(b);pending+=b
      while len(pending)>=4:
       n=int.from_bytes(pending[2:4],'big')
       if len(pending)<n:break
       records.append({'direction':direction,'hex':pending[:n].hex()});pending=pending[n:]
    finally:
     try:dst.shutdown(socket.SHUT_WR)
     except OSError:pass
   a=threading.Thread(target=relay,args=(client,server,'request'));b=threading.Thread(target=relay,args=(server,client,'response'));a.start();b.start();a.join();b.join()
server=subprocess.Popen([str(root/'examples/server_example_basic_io/server_example_basic_io'),'18102'],cwd=root,stdout=subprocess.DEVNULL)
try:
 time.sleep(.3); p=threading.Thread(target=proxy);p.start();ready.wait()
 result=subprocess.run([str(root/'audit_client')],capture_output=True,text=True,timeout=15);p.join(timeout=5)
 Path('/tmp/stateafl-mms-fixtures.json').write_text(json.dumps({'commit':'6d231326bff8e9b6500aa1e345c076d3a329f211','result':result.stdout,'records':records},indent=2)+'\n')
 print(result.stdout);print(json.dumps(records,indent=2))
finally:server.terminate();server.wait()
