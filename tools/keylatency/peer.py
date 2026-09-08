import json, subprocess, sys, time, base64, re, threading, queue
DVV="/Applications/DeskVNCViewer.app/Contents/MacOS/dvv"
class Peer:
    def __init__(self):
        self.p=subprocess.Popen([DVV,"mcp","--stdio"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        self.n=0; self.q=queue.Queue()
        threading.Thread(target=self._reader,daemon=True).start()
        self.rpc("server/discover",{})
    def _reader(self):
        for line in self.p.stdout:
            line=line.strip()
            if line:
                try: self.q.put(json.loads(line))
                except Exception: pass
    def rpc(self,method,params,timeout=30):
        self.n+=1; i=self.n
        self.p.stdin.write(json.dumps({"jsonrpc":"2.0","id":i,"method":method,"params":params})+"\n"); self.p.stdin.flush()
        t0=time.time()
        while time.time()-t0<timeout:
            try: m=self.q.get(timeout=timeout)
            except queue.Empty: break
            if m.get("id")==i: return m
        raise TimeoutError(method)
    def call(self,name,args,timeout=30):
        m=self.rpc("tools/call",{"name":name,"arguments":args},timeout)
        if "error" in m: return {"error":m["error"]}
        r=m["result"]; out={"text":"","json":None,"images":[]}
        for c in r.get("content",[]):
            if c.get("type")=="text":
                out["text"]+=c["text"]
                mm=re.search(r"```dvv\n(.*?)```",c["text"],re.S)
                if mm:
                    try: out["json"]=json.loads(mm.group(1))
                    except Exception: pass
            elif c.get("type")=="image": out["images"].append(base64.b64decode(c["data"]))
        out["isError"]=r.get("isError",False)
        return out
if __name__=="__main__":
    pr=Peer()
    r=pr.call("dvv_open",{"hostId":sys.argv[1],"perceive":True}); print(r["text"][:200])
    limb=r["json"]["limb"]["limb_id"] if r["json"] else None
    print("limb",limb)
    print(pr.call("dvv_wait",{"limbId":limb,"until":"connected","timeout":8000})["text"][:200])
    s=pr.call("dvv_screen",{"limbId":limb,"form":"full","scale":0.5})
    print(s["text"][:300]); 
    for k,img in enumerate(s["images"]): open(f"screen{k}.png","wb").write(img); print("saved",len(img))
    print(json.dumps(pr.call("dvv_status",{"limbId":limb})["json"])[:600])
