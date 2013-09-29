import wx
import pefile
import avcheck
import analysis
import os
class maingui(wx.Frame):

 def __init__(self,parent,title):
  wx.Frame.__init__(self,parent,title=title,size=(400,300))
  self.contents=""
  filemenu = wx.Menu()
  self.CreateStatusBar()
  opn=filemenu.Append(wx.ID_ANY, "&Open","Open a new file")
  self.Bind(wx.EVT_MENU,self.OnOpen,opn)
  filemenu.AppendSeparator()
  about=filemenu.Append(wx.ID_ABOUT,"&About","About PyTriage")
  filemenu.AppendSeparator()
  self.Bind(wx.EVT_MENU,self.OnAbout,about)
  exit=filemenu.Append(wx.ID_EXIT,"E&xit","Quit the program")
  self.Bind(wx.EVT_MENU,self.OnExit,exit)
  infomenu=wx.Menu()
  ha=infomenu.Append(wx.ID_ANY,"&Run analysis","")
  self.Bind(wx.EVT_MENU,self.RunAn,ha)
  advmenu=wx.Menu()
  impo=advmenu.Append(wx.ID_ANY,"&Imports and Exports","Get a list of imported and exported functions")
  self.Bind(wx.EVT_MENU,self.ImporEx,impo)
  submenu=wx.Menu()
  virtot=submenu.Append(wx.ID_ANY,"VirusTotal","Submit to VirusTotal for analysis")
  self.Bind(wx.EVT_MENU,self.VirTot,virtot)
  genmenu=wx.Menu()
  clamavsig=genmenu.Append(wx.ID_ANY,"ClamAV","Generate ClamAV signature")
  self.Bind(wx.EVT_MENU,self.ClamAV,clamavsig)
  yarasig=genmenu.Append(wx.ID_ANY,"YARA","Generate YARA signature")
  self.Bind(wx.EVT_MENU,self.YaraSig,yarasig)
  repmenu=wx.Menu()
  reportm=repmenu.Append(wx.ID_ANY,"Generate Generic Report","Generates a report on PE file characteristics")
  self.Bind(wx.EVT_MENU,self.report_m,reportm)
  menu=wx.MenuBar()
  menu.Append(filemenu,"&File")
  menu.Append(infomenu,"&Info")
  menu.Append(advmenu,"&Advanced")
  menu.Append(submenu,"&Submit")
  menu.Append(genmenu,"&Generate")
  menu.Append(repmenu,"&Report")
  self.SetMenuBar(menu)
  self.Show(True)

 def OnOpen(self,e):
   self.dirname=''
   dlgO= wx.FileDialog(self,"Choose a file",self.dirname,"","*.*",wx.OPEN)
   if dlgO.ShowModal()== wx.ID_OK:
     self.filename=dlgO.GetFilename()
     self.dirname=dlgO.GetDirectory()
     malw=open(os.path.join(self.dirname,self.filename),'r')
     self.contents=malw.read()
     dlgO2=wx.MessageDialog(self,"Opened file: "+self.filename,"PyTriage",wx.OK)
     dlgO2.ShowModal()
     dlgO2.Destroy()
     malw.close()
   dlgO.Destroy()
 def RunAn(self,e):
  self.box=wx.BoxSizer(wx.VERTICAL)
  self.control=[]
  self.panels=[]
  for i in range(3):
   self.panels.append(wx.Panel(self))
   self.box.Add(self.panels[i],.5,wx.EXPAND)
   self.control.append(wx.TextCtrl(self,style=wx.TE_MULTILINE|wx.TE_READONLY))
   self.box.Add(self.control[i],1,wx.EXPAND)
  self.SetAutoLayout(True)
  wx.StaticText(self.panels[0],-1,"Filetype",style=wx.ALIGN_CENTER_HORIZONTAL)
  self.control[0].SetValue(analysis.filetype(self.contents))
  wx.StaticText(self.panels[1],-1,"Hashes")
  self.control[1].SetValue("MD5:"+analysis.hashes(self.contents)[0]+"\nSHA1:"+analysis.hashes(self.contents)[1])
  wx.StaticText(self.panels[2],-1,"PE Sections")
  self.control[2].SetValue("\n".join((analysis.peinfo(self.contents))))
  self.SetSizer(self.box)
  self.Layout()
	 
 def ImporEx(self,e):
	 self.rows=wx.BoxSizer(wx.HORIZONTAL)
	 self.column=[]
	 self.column.append(wx.TextCtrl(self,style=wx.TE_MULTILINE|wx.TE_READONLY))
	 self.column.append(wx.TextCtrl(self,style=wx.TE_MULTILINE|wx.TE_READONLY))
	 for i in self.column:
		 self.rows.Add(i,1,wx.EXPAND)
	 self.SetAutoLayout(True)
	 importdata= analysis.peimport(self.contents)
	 importstr=""
	 for i in range(len(importdata)):
		 if i%2==0:
			 importstr+=importdata[i]+"\n"
		 else:
			 for i in importdata[i]: 
			   importstr+= "	"+i+"\n"
	 self.column[0].SetValue("Imports\n"+importstr)
	 self.column[1].SetValue("Exports\n"+"\n".join(analysis.peexport(self.contents)))
	 self.SetSizer(self.rows)
	 self.Layout()
	 
 def VirTot(self,e):
     self.virresult=wx.BoxSizer(wx.VERTICAL)
     self.virbox=wx.TextCtrl(self,style=wx.TE_MULTILINE|wx.TE_READONLY)
     self.virresult.Add(self.virbox,1,wx.EXPAND)
     self.SetSizer(self.virresult)
     self.Layout()
     self.virbox.SetValue(avcheck.check(analysis.hashes(self.contents)[0],self.filename))
     
 def ClamAV(self,e):
	 analysis.clams(self.contents)
	 dlgC=wx.MessageDialog(self,"ClamAV signatures written to clam.hdb","PyTriage",wx.OK)
	 dlgC.ShowModal()
	 dlgC.Destroy()

 def YaraSig(self,e):
	 analysis.yarac(analysis.printable(self.contents))
	 dlgY=wx.MessageDialog(self,"YARA signatures written to sig.yara","PyTriage",wx.OK)
	 dlgY.ShowModal()
	 dlgy.Destroy()
	 
 def report_m(self,e):
	 pe=pefile.PE(data=self.contents)
	 info_m=pe.dump_info()
	 open("Report.txt","w").write(info_m)

 def OnAbout(self,e):
   dlgA= wx.MessageDialog(self,"PyTriage is an open source malware analysis tool developed by Sp3ctr3 aka Yashin Mehaboobe","About",wx.OK)
   dlgA.ShowModal()
   dlgA.Destroy()
 
 def OnExit(self,e):
   self.Close(True)

app=wx.App(False)
frame=maingui(None,"PyTriage")
app.MainLoop()
