import netifaces
from Tkinter import *
from ttk import *
from scapy.all import *

interfaces = {}

def addr2bin(addr):
	binary = ""
	for num in addr.split("."):
		b = str(bin(int(num))).split("b")[1]
		binary += "0"*(8-len(b))+b
	return binary

def bin2addr(bin):
	addr = []
	for n in range(0,32,8):
		addr.append(str(int(bin[n:n+8],2)))
	return ".".join(addr)

def red(ip,mask):
	ip_bin = addr2bin(ip)
	mask_bin = addr2bin(mask)
	red_bin = ""
	for x,y in zip(ip_bin,mask_bin):
		red_bin += "1" if x == y == "1" else "0"
	return bin2addr(red_bin)

def broadcast(red,mask):
	red_bin = addr2bin(red)
	mask_num = addr2bin(mask).count("1")
	broadcast_bin = red_bin[0:mask_num]+"1"*(32-mask_num)
	return bin2addr(broadcast_bin)

for iff in netifaces.interfaces():
	addrs = netifaces.ifaddresses(iff)
	interfaces[iff] = {}
	if 17 in addrs:
		interfaces[iff]["mac"] = addrs[17][0]["addr"]
	if 2 in addrs:
		interfaces[iff]["ip"] = addrs[2][0]["addr"]
		interfaces[iff]["mask"] = addrs[2][0]["netmask"]

interfaces = {iff:interfaces[iff] for iff in interfaces 
		if iff != "lo" and len(interfaces[iff].values()) == 3}

for iff in interfaces:
	ip = interfaces[iff]["ip"]
	mask = interfaces[iff]["mask"]
	interfaces[iff]["red"] = red(ip,mask)
	interfaces[iff]["broadcast"] = broadcast(interfaces[iff]["red"],mask)

for iff in interfaces:
	print iff, interfaces[iff]

class InfoInterfaces():
	def __init__(self,master):
		interface_label = Label(master.frame,text="Interface:")
		interface_label.grid(column=0,row=0,padx=5,pady=5,sticky=W)

		self.combobox = Combobox(master.frame,state="readonly",width=15)
		self.combobox["values"] = [x for x in interfaces]
		self.combobox.grid(column=1,row=0,padx=5,pady=5,sticky=W)
		self.combobox.current(0)
		self.combobox.bind("<<ComboboxSelected>>", self.iface_selec)

		self.interface_selec = self.combobox["values"][self.combobox.current()]
		self.ip = interfaces[self.interface_selec]["ip"]
		self.mask = interfaces[self.interface_selec]["mask"]
		self.num_mask = str(addr2bin(self.mask).count("1"))
		self.red = interfaces[self.interface_selec]["red"]
		self.broadcast = interfaces[self.interface_selec]["broadcast"]

		self.ip_label =  Label(master.frame,text=str(self.ip))
		self.mask_label = Label(master.frame,text=str(self.mask)+" /"+self.num_mask)
		self.red_label = Label(master.frame,text=str(self.red))
		self.broadcast_label = Label(master.frame,text=str(self.broadcast))

		Label(master.frame,text="IP:").grid(column=0,row=1,padx=5,pady=5,sticky=W)
		Label(master.frame,text="NetMask:").grid(column=0,row=2,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Network:").grid(column=0,row=3,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Broadcast:").grid(column=0,row=4,padx=5,pady=5,sticky=W)

		self.ip_label.grid(column=1,row=1,padx=5,pady=5,sticky=W)
		self.mask_label.grid(column=1,row=2,padx=5,pady=5,sticky=W)
		self.red_label.grid(column=1,row=3,padx=5,pady=5,sticky=W)
		self.broadcast_label.grid(column=1,row=4,padx=5,pady=5,sticky=W)

		self.escanear = Button(master.frame,text="Escanear",command=master.escaneo)
		self.escanear.grid(column=1,row=5,padx=5,pady=10,sticky=W)

	def iface_selec(self,event):
		self.interface_selec = self.combobox["values"][self.combobox.current()]
		self.ip = interfaces[self.interface_selec]["ip"]
		self.mask = interfaces[self.interface_selec]["mask"]
		self.num_mask = str(addr2bin(self.mask).count("1"))
		self.red = interfaces[self.interface_selec]["red"]
		self.broadcast = interfaces[self.interface_selec]["broadcast"]

		self.ip_label["text"] =  str(self.ip)
		self.mask_label["text"] = str(self.mask)+" /"+self.num_mask
		self.red_label["text"] = str(self.red)
		self.broadcast_label["text"] = str(self.broadcast)

class Host():
	def __init__(self,master,ip,mac,n_r):
		self.ip = ip
		self.mac = mac
		self.label_ip_host = Label(master.frame_equipos,text=self.ip)
		self.label_mac_host = Label(master.frame_equipos,text=self.mac)
		self.button_spoof = Button(master.frame_equipos,text="SPOOF",command=lambda: self.spoof(self.ip,self.mac))

		self.label_ip_host.grid(row=n_r,column=0,padx=5,pady=5,sticky=W)
		self.label_mac_host.grid(row=n_r,column=1,padx=5,pady=5,sticky=W)
		self.button_spoof.grid(row=n_r,column=2,padx=5,pady=5,sticky=W)

	def spoof(self,ip,mac):
		print "spoof to ", ip, mac
		

class App():
	def __init__(self):
		self.root = Tk()
		self.frame = Frame(borderwidth=2,relief="groove")
		self.frame.grid(row=0,column=0,columnspan=2,sticky=W+E,padx=5,pady=5)

		self.Iinterfaces = InfoInterfaces(self)

		self.canvas = Canvas(self.root,width=330)		
		self.frame_equipos = Frame(self.canvas)
		yscroll = Scrollbar(self.root,orient=VERTICAL,command=self.canvas.yview)
		self.canvas.configure(yscrollcommand=yscroll.set)

		def onFrameConfigure(canvas):
			canvas.configure(scrollregion=canvas.bbox("all"))

		self.frame_equipos.bind("<Configure>",lambda event,canvas=self.canvas: onFrameConfigure(self.canvas))

		self.canvas.grid(row=1,column=0,sticky=N+W+E+S,padx=5,pady=5)
		self.canvas.create_window((0,0),window=self.frame_equipos, anchor=N, width=330)
		yscroll.grid(row=1,column=1, sticky="ns", pady=5)

		self.equipos_escaneo = []
		self.hosts = []
		
		self.root.resizable(width=False,height=True)
		self.root.minsize(width=350, height=250)

		self.root.rowconfigure(1, weight=1)

		self.root.mainloop()

	def escaneo(self):
		self.equipos_escaneo = []
		self.hosts = []
		if self.frame_equipos.winfo_children():
			for widget in self.frame_equipos.winfo_children():
    				widget.destroy()
		print "Escaneando "+self.Iinterfaces.combobox["values"][self.Iinterfaces.combobox.current()]+"...."
		alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.Iinterfaces.ip+"/"+self.Iinterfaces.num_mask), timeout=1, verbose=0)
		print "Escaneo Finalizado."
		for i in range(0,len(alive)):
			self.equipos_escaneo.append([alive[i][1].psrc,alive[i][1].hwsrc])
		n_r = 0
		for equipo in self.equipos_escaneo:
			self.hosts.append(Host(self,equipo[0],equipo[1],n_r))
			n_r += 1

if interfaces:
	app = App()
else:
	print "No Network configuration"
		
