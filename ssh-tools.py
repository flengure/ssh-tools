import io
from tkinter import ttk
import customtkinter as ctk
from openssh_wrapper import SSHConnection

root = ctk.CTk()
root.title('ssh-edit')
root.geometry('680x680')

global conn

aclDir = "/etc/firewall/user"
cmdRestartFirewall = "fw4 restart"
cmdListSet = 'nft list set inet fw4 '
cmdListDNS = 'cat /etc/dnsmasq.d/'
cmdArp ='f=\'%-18s %-17s %-10s\n\';ip neigh show | awk -v f="$f" \'BEGIN{'
cmdArp += 'printf f, "-----------------", "---------------", "---------";'
cmdArp += 'printf f, "Hardware Address", "IP Adress", "State";'
cmdArp += 'printf f, "-----------------", "---------------", "---------"}'
cmdArp += '!/FAILED|INCOMPLETE/{printf f, $5, $1, $6}\''
editList = {
    "src_accept":  (aclDir + "/src_accept.txt",  cmdRestartFirewall ),
    "src_reject":  (aclDir + "/src_reject.txt",  cmdRestartFirewall ),
    "dest_accept": (aclDir + "/dest_accept.txt", cmdRestartFirewall ),
    "dest_reject": (aclDir + "/dest_reject.txt", cmdRestartFirewall ),
    "authorized_keys": ("/etc/dropbear/authorized_keys", "" ),
    "hosts": ("/etc/hosts", "" ),
}
viewList = {
    "src_accept":  'for i in src_accept_ipv6 src_accept_ipv4 src_accept_mac; do ' + cmdListSet + '$i; done',
    "src_reject":  'for i in src_reject_ipv6 src_reject_ipv4 src_reject_mac; do ' + cmdListSet + '$i; done',
    "dest_accept": 'for i in dest_accept_ipv6 dest_accept_ipv4; do ' + cmdListSet + '$i; done; printf "%s\n" "' + cmdListDNS + 'dest_accept.conf";' + cmdListDNS + 'dest_accept.conf',
    "dest_reject": 'for i in dest_reject_ipv6 dest_reject_ipv4; do ' + cmdListSet + '$i; done; printf "%s\n" "' + cmdListDNS + 'dest_reject.conf";' + cmdListDNS + 'dest_reject.conf',
    "arp table": cmdArp,
}

hostSpec = ctk.StringVar(root)
editItem = ctk.StringVar(root)
viewItem = ctk.StringVar(root)

hostSpec.set('41.79.7.60:8021')
editItem.set('src_accept')
viewItem.set('src_accept')

btnCnct_fg_color_1 = ['#3B8ED0', '#1F6AA5'] 
btnCnct_fg_color_2 = 'green' 

def connect():
    global conn
    host, port = entHost.get(), 0
    if ":" in host:
        host, port = host.split(":")
    conn = SSHConnection( host, port = port, login = 'root' )

def get_view():
    connect()
    txtView.delete('1.0','end')
    results = conn.run(viewList[viewItem.get()])
    if results.returncode == 0:
        txtView.insert('1.0',results)
    else:
        tk.messagebox.showerror(title='ssh-edit', message=results.stderr.decode("utf-8"))
        txtView.insert('1.0',results.stderr)

def get_file():
    connect()
    txtEdit.delete('1.0','end')
    results = conn.run('cat ' + editList[editItem.get()][0])
    if results.returncode == 0:
        txtEdit.insert('1.0',results)
    else:
        tk.messagebox.showerror(title='ssh-edit', message=results.stderr.decode("utf-8"))
        txtEdit.insert('1.0',results.stderr)

def set_file():
    connect()
    contents = txtEdit.get('1.0','end')
    try:
        conn.scp((io.StringIO(contents), ), target=editList[editItem.get()][0], mode='0644')
    except:
        tk.messagebox.showerror(title='ssh-edit', message='error')
    else:
        cmd = editList[editItem.get()][1]
        if not cmd == "": 
            try:
                conn.run(cmd)
            except:
                tk.messagebox.showerror(title='ssh-edit', message='error')

def editItem_change(*args):
    get_file()
    return

def viewItem_change(*args):
    get_view()
    return

def hostSpec_change(*args):
    return

editItem.trace("w", editItem_change)
viewItem.trace("w", viewItem_change)
hostSpec.trace("w", hostSpec_change)

root.columnconfigure(0, weight=1)
root.rowconfigure(1, weight=1)

entHost = ctk.CTkEntry(root, textvariable = hostSpec, )
entHost.grid(row=0, column=0, padx=10, pady=10, sticky="news")

tabs = ttk.Notebook(root)
tabs.grid(row=1, column=0, columnspan=1, padx=0, pady=0, sticky='news')

editor = ctk.CTkFrame(tabs)
editor.columnconfigure(0, weight=1)
editor.columnconfigure(1, weight=1)
editor.columnconfigure(2, weight=1)
editor.rowconfigure(1, weight=1)
editor.pack(fill='both', expand=1)

tabs.add(editor, text = "Editor")

optEdit = ctk.CTkOptionMenu(editor, variable = editItem, values = list(editList.keys()))
optEdit.grid(row=0, column=0, padx=10, pady=10, sticky='ew')

btnEditGet = ctk.CTkButton(editor, text = 'Load', command = get_file)
btnEditGet.grid(row=0, column=1, padx=10, pady=10, sticky='news')

btnEditSet = ctk.CTkButton(editor, text = 'Save', command = set_file)
btnEditSet.grid(row=0, column=2, padx=10, pady=10, sticky='news')

txtEdit = ctk.CTkTextbox(editor, wrap='word', width = 200, font=("Courier New", 12))
txtEdit.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky='news')

viewer = ctk.CTkFrame(tabs)
viewer.columnconfigure(0, weight=1)
viewer.columnconfigure(1, weight=1)
viewer.rowconfigure(1, weight=1)
viewer.pack(fill='both', expand=1)

tabs.add(viewer, text = "Sets")

optView = ctk.CTkOptionMenu(viewer, variable = viewItem, values = list(viewList.keys()))
optView.grid(row=0, column=0, padx=10, pady=10, sticky='ew')

btnView = ctk.CTkButton(viewer, text = 'Load', command = get_view)
btnView.grid(row=0, column=1, padx=10, pady=10, sticky='news')

txtView = ctk.CTkTextbox(viewer, wrap='word', width = 200, font=("Courier New", 12))
txtView.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky='news')

root.mainloop()