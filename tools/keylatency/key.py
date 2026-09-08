import ctypes, ctypes.util, time, sys, datetime, subprocess
Q=ctypes.cdll.LoadLibrary(ctypes.util.find_library("ApplicationServices"))
Q.CGEventCreateKeyboardEvent.restype=ctypes.c_void_p
Q.CGEventCreateKeyboardEvent.argtypes=[ctypes.c_void_p,ctypes.c_uint16,ctypes.c_bool]
Q.CGEventPost.argtypes=[ctypes.c_uint32,ctypes.c_void_p]
CF=ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))
CF.CFRelease.argtypes=[ctypes.c_void_p]
def key(code,down):
    e=Q.CGEventCreateKeyboardEvent(None,code,down); Q.CGEventPost(0,e); CF.CFRelease(e)
def now(): return datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
codes={"shift":56,"a":0,"s":1,"d":2,"f":3,"bs":51}
seq=sys.argv[1].split(",") if len(sys.argv)>1 else ["shift"]*5
gap=float(sys.argv[2]) if len(sys.argv)>2 else 0.25
subprocess.run(["osascript","-e",'tell application "DeskVNCViewer" to activate'])
time.sleep(0.6)
fm=subprocess.run(["osascript","-e",'tell application "System Events" to get name of first application process whose frontmost is true'],capture_output=True,text=True).stdout.strip()
print("frontmost",fm)
for k in seq:
    c=codes[k]
    print("POST",k,"down",now()); key(c,True)
    time.sleep(0.03)
    print("POST",k,"up  ",now()); key(c,False)
    time.sleep(gap)
