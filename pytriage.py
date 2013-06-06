import sys
import analysis
import avcheck
import curses 
import os
global data
global hashes
global filename
data=""
hashes=""
def file_m():
  global data
	global filename
	s = curses.newwin(6,10,2,1)
	s.box()
	s.addstr(1,2,"O",hotkey)
	s.addstr(1,3,"pen")
	s.addstr(2,2,"Q",hotkey)
	s.addstr(2,3,"uit")
	s.refresh()
	k=s.getch()
	if k==ord("o"):
		files=os.listdir(os.getcwd())
		n=curses.newwin(len(files)+2,30,5,30)
		n.box()
		n.refresh()
		for i in range(len(files)):
			n.addstr(i+1,1,str(i)+")"+files[i])
		sel=n.getch()
		n.erase()
		n.box()
		n.refresh()
		data=open((files[int(sel)-48])).read()
		filename=files[int(sel)-48]
		n.addstr((len(files))/2,1,"Opened:"+files[int(sel)-48])
		n.getch()
	elif k==ord("q"):
		curses.endwin()
		sys.exit()
	screen.hline(2, 1, curses.ACS_HLINE, 77)
	s.refresh()

def info_m():
	if data is not "":
	 s = curses.newwin(19,77,3,1)
	 s.box()
	 s.hline(4, 1, curses.ACS_HLINE, 75)
	 s.addstr(1,2,"File: "+filename)
	 s.hline(2, 1, curses.ACS_HLINE, 75)
	 s.addstr(3,32,"ANALYSIS",curses.A_BOLD)
	 global hashes
	 hashes=analysis.hashes(data)
	 s.addstr(5,32,"Hashes",curses.A_UNDERLINE)
	 s.addstr(6,1,"MD5:"+hashes[0])
	 s.addstr(7,1,"SHA1:"+hashes[1])
	 s.hline(8, 1, curses.ACS_HLINE, 75)
	 s.addstr(9,32,"PE Section",curses.A_UNDERLINE)
	 pe=analysis.peinfo(data)
	 for i in range(len(pe)):
	  s.addstr(10+i,1,pe[i])
	 s.hline(14, 1, curses.ACS_HLINE, 75)
	 s.addstr(15,32,"File Type",curses.A_UNDERLINE)
	 s.addstr(16,1,analysis.filetype(data))
	 s.refresh()
	 k=s.getch()
	 s.erase()
	 s.refresh()

def adv_m():
	if data is not "":
	 s = curses.newwin(19,77,3,1)
	 s.box()
	 EP=analysis.ep(data)
	 if EP is not "error":
	  s.addstr(1,32,"Entry Point: "+hex(EP))
	 s.hline(2, 1, curses.ACS_HLINE, 75)
	 s.vline(3, 40, curses.ACS_VLINE, 15)
	 s.addstr(3,10,"Imports",hotkey)
	 imports=analysis.peimport(data)
	 for value in range(len(imports)):
	  s.addstr(value+5,1,imports[value])
	 s.addstr(3,50,"Exports",hotkey)
	 exports=analysis.peexport(data)
	 for value in range(len(exports)):
	  s.addstr(value+5,45,exports[value])
	 s.refresh()
	 k=s.getch()
	 s.erase()
	 s.refresh()

def submit_m():
	if data is not "" and hashes is not "":
	 s = curses.newwin(4,40,5,25)
	 s.box()
	 s.addstr(1,1,avcheck.check(hashes[0],filename))
	 s.getch()
	 s.erase()
	 s.refresh()
	
def generate_m():
	if data is not "":
	 s = curses.newwin(4,30,5,30)
	 s.box()
	 s.addstr(1,1,"C",hotkey)
	 s.addstr(1,2,"lamAV")
	 s.addstr(2,1,"Y",hotkey)
	 s.addstr(2,2,"ara")
	 k=s.getch()
	 if k==ord("c"):
	  analysis.clams(data)
	  s.erase()
	  s.addstr(1,1,"Signature written to clam.hdb")
	  s.refresh()
	 if k==ord("y"):
	  analysis.yarac(analysis.printable(data))
	  s.erase()
	  s.addstr(1,1,"Signature written to sig.yara")
	  s.refresh()
	  s.getch()
	  s.erase()
	  s.refresh()

if __name__=="__main__":
 stdscr = curses.initscr() 
 curses.start_color()
 curses.noecho() 
 curses.curs_set(0) 
 curses.init_pair(1, curses.COLOR_RED, curses.COLOR_WHITE)
 stdscr.keypad(1) 
 global screen
 hotkey=curses.color_pair(1)
 screen = stdscr.subwin(23, 79, 0, 0)
 screen.box()
 screen.hline(2, 1, curses.ACS_HLINE, 77)
 screen.addstr(1,1,"F",hotkey)
 screen.addstr(1,2,"ile")
 screen.hline(1,10,curses.ACS_VLINE,1)
 screen.addstr(1,11,"I",hotkey)
 screen.addstr(1,12,"nfo")
 screen.hline(1,20,curses.ACS_VLINE,1)
 screen.addstr(1,21,"A",hotkey)
 screen.addstr(1,22,"dvanced")
 screen.hline(1,30,curses.ACS_VLINE,1)
 screen.addstr(1,31,"S",hotkey)
 screen.addstr(1,32,"ubmit")
 screen.hline(1,40,curses.ACS_VLINE,1)
 screen.addstr(1,41,"G",hotkey)
 screen.addstr(1,42,"enerate")
 screen.refresh()
 while True: 
    event = screen.getch() 
    if event == ord("q"): break 
    elif event == ord("f"):
 		file_m()
    elif	event == ord("i"):
 		info_m()
    elif event == ord("g"):
 		generate_m()
    elif event==ord("s"):
 		submit_m()
    elif event==ord("a"):
 		adv_m()
 curses.endwin()

