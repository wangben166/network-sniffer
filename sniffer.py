"""教学用网络嗅探器：Npcap/libpcap 捕获，Scapy 解码，Tk 界面。"""
import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


from scapy.all import (conf, AsyncSniffer, get_if_list, get_if_addr, rdpcap, wrpcap,
                       IP, IPv6, TCP, UDP, ICMP, Raw)

LIMIT = 20000
HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ', b'HTTP/1.')


def is_http(p):
    return TCP in p and Raw in p and bytes(p[Raw].load).startswith(HTTP_METHODS)


def matches(p, choice):
    if choice == '全部': return True
    if choice == 'HTTP': return is_http(p)
    if choice == 'ICMP': return ICMP in p or (IPv6 in p and any(x.name.startswith('ICMPv6') for x in layers(p)))
    return {'TCP': TCP, 'UDP': UDP, 'IPv4': IP, 'IPv6': IPv6}[choice] in p


def layers(p):
    while p:
        yield p
        p = p.payload


def endpoints(p):
    ip = p.getlayer(IP) or p.getlayer(IPv6)
    if not ip: return '', ''
    return ip.src, ip.dst


def protocol(p):
    if is_http(p): return 'HTTP'
    for layer, name in ((TCP, 'TCP'), (UDP, 'UDP'), (ICMP, 'ICMP')):
        if layer in p: return name
    for layer in layers(p):
        if layer.name.startswith('ICMPv6'): return 'ICMPv6'
    return 'IPv6' if IPv6 in p else 'IPv4' if IP in p else p.name


def flow_key(p):
    if TCP not in p: return None
    src, dst = endpoints(p)
    if not src: return None
    return tuple(sorted(((src, int(p[TCP].sport)), (dst, int(p[TCP].dport)))))


class App:
    def __init__(self, root):
        self.root = root
        root.title('网络嗅探器 | 课程实验A1')
        root.geometry('1250x800')
        self.packets = []
        self.q = queue.Queue(maxsize=10000)
        self.dropped = 0
        self.sniffer = None
        self.generation = 0
        self.running = False
        self.ifaces = []
        root.minsize(960, 650)
        root.configure(bg='#eef2f7')
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI', 9), background='#eef2f7', foreground='#24344c')
        style.configure('TButton', padding=(12, 7), background='#ffffff', borderwidth=1)
        style.map('TButton', background=[('active', '#e3ebf6'), ('disabled', '#eef2f7')], foreground=[('disabled', '#9aa7b7')])
        style.configure('Primary.TButton', background='#2463eb', foreground='white', borderwidth=0)
        style.map('Primary.TButton', background=[('active', '#1d4ed8'), ('disabled', '#b8c8e3')], foreground=[('disabled', '#f1f5f9')])
        style.configure('Treeview', background='#ffffff', fieldbackground='#ffffff', foreground='#25344a', rowheight=29, borderwidth=0)
        style.configure('Treeview.Heading', background='#e9eff7', foreground='#53647d', font=('Microsoft YaHei UI', 9, 'bold'), relief='flat', padding=(6, 7))
        style.map('Treeview', background=[('selected', '#d7e7ff')], foreground=[('selected', '#153f80')])
        style.configure('TCombobox', padding=4)
        style.configure('TEntry', padding=5)

        header = tk.Frame(root, bg='#14253e', padx=20, pady=13); header.pack(fill='x')
        tk.Label(header, text='网络嗅探器', bg='#14253e', fg='white', font=('Microsoft YaHei UI', 17, 'bold')).pack(side='left')
        tk.Label(header, text='  /  NETWORK PACKET ANALYZER', bg='#14253e', fg='#9aafca', font=('Segoe UI', 9)).pack(side='left', padx=8)
        tk.Label(header, text='软件与系统安全 · 课程实验', bg='#14253e', fg='#b6c8dd', font=('Microsoft YaHei UI', 9)).pack(side='right')

        bar = ttk.Frame(root, padding=(16, 12, 16, 5)); bar.pack(fill='x')
        ttk.Label(bar, text='捕获网卡').pack(side='left', padx=(0, 6))
        self.interface = ttk.Combobox(bar, width=42, state='readonly'); self.interface.pack(side='left', fill='x', expand=True, padx=(0, 6))
        ttk.Button(bar, text='刷新', command=self.refresh).pack(side='left', padx=(0, 10))
        self.start_btn = ttk.Button(bar, text='▶  开始抓包', command=self.start, style='Primary.TButton'); self.start_btn.pack(side='left', padx=(0, 6))
        self.stop_btn = ttk.Button(bar, text='■  停止', command=self.stop, state='disabled'); self.stop_btn.pack(side='left')

        filters = ttk.Frame(root, padding=(16, 4, 16, 10)); filters.pack(fill='x')
        ttk.Label(filters, text='捕获过滤  BPF').pack(side='left', padx=(0, 6))
        self.bpf = ttk.Entry(filters, width=24); self.bpf.pack(side='left', padx=(0, 14))
        ttk.Label(filters, text='显示过滤').pack(side='left', padx=(0, 6))
        self.filter = ttk.Combobox(filters, values=['全部','HTTP','TCP','UDP','IPv4','IPv6','ICMP'], state='readonly', width=8)
        self.filter.set('全部'); self.filter.pack(side='left', padx=(0, 10)); self.filter.bind('<<ComboboxSelected>>', lambda e:self.rebuild())
        ttk.Button(filters, text='追踪 TCP 流', command=self.show_flow).pack(side='left')
        ttk.Button(filters, text='清空', command=self.clear).pack(side='right', padx=(6, 0))
        ttk.Button(filters, text='保存 PCAP', command=self.save_file).pack(side='right', padx=(6, 0))
        ttk.Button(filters, text='打开 PCAP', command=self.open_file).pack(side='right')

        pane = ttk.Panedwindow(root, orient='vertical'); pane.pack(fill='both', expand=True, padx=16)
        table = ttk.Frame(pane); pane.add(table, weight=4)
        tk.Label(table, text='数据包列表', bg='#eef2f7', fg='#263a55', font=('Microsoft YaHei UI', 10, 'bold'), anchor='w', pady=5).pack(fill='x')
        table_body = ttk.Frame(table); table_body.pack(fill='both', expand=True)
        cols = ('no','time','src','dst','proto','len','info')
        self.tree = ttk.Treeview(table_body, columns=cols, show='headings', selectmode='browse')
        for c, title, width in zip(cols, ('序号','时间','源地址','目标地址','协议','长度','摘要'), (65,125,180,180,80,70,450)):
            self.tree.heading(c, text=title); self.tree.column(c, width=width, stretch=c=='info')
        scroll = ttk.Scrollbar(table_body, orient='vertical', command=self.tree.yview); self.tree.configure(yscrollcommand=scroll.set)
        xscroll = ttk.Scrollbar(table_body, orient='horizontal', command=self.tree.xview); self.tree.configure(xscrollcommand=xscroll.set)
        scroll.pack(side='right', fill='y'); xscroll.pack(side='bottom', fill='x'); self.tree.pack(side='left', fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.select)
        self.tree.tag_configure('even', background='#f5f8fc')

        def text_panel(title):
            frame = ttk.Frame(pane); pane.add(frame, weight=2)
            tk.Label(frame, text=title, bg='#eef2f7', fg='#263a55', font=('Microsoft YaHei UI', 10, 'bold'), anchor='w', pady=5).pack(fill='x')
            body = ttk.Frame(frame); body.pack(fill='both', expand=True)
            text = tk.Text(body, height=7, wrap='none', font=('Consolas', 10), bg='#ffffff', fg='#26364e', relief='flat', padx=10, pady=8, insertbackground='#2463eb')
            sy = ttk.Scrollbar(body, orient='vertical', command=text.yview); sx = ttk.Scrollbar(body, orient='horizontal', command=text.xview)
            text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            sy.pack(side='right', fill='y'); sx.pack(side='bottom', fill='x'); text.pack(fill='both', expand=True)
            return text
        self.details = text_panel('协议详情  /  PACKET DETAILS')
        self.hex = text_panel('原始字节  /  HEX & ASCII')
        status_bar = tk.Frame(root, bg='#e1e9f3', padx=16, pady=8); status_bar.pack(fill='x', pady=(10, 0))
        self.status = tk.StringVar(value='就绪 · 选择网卡后开始抓包')
        tk.Label(status_bar, textvariable=self.status, bg='#e1e9f3', fg='#425773', font=('Microsoft YaHei UI', 9), anchor='w').pack(side='left', fill='x', expand=True)
        tk.Label(status_bar, text='仅捕获授权网络流量', bg='#e1e9f3', fg='#71839b', font=('Microsoft YaHei UI', 9)).pack(side='right')
        self.refresh(); root.after(100, self.poll); root.protocol('WM_DELETE_WINDOW', self.close)

    def refresh(self):
        try:
            self.ifaces = list(conf.ifaces.values())
            labels = [f'{x.name} | {x.description} | {x.ip or ""}' for x in self.ifaces]
            self.interface['values'] = labels
            if labels: self.interface.current(0)
        except Exception as e: messagebox.showerror('网卡错误', str(e))

    def start(self):
        if self.interface.current() < 0:
            messagebox.showerror('无法开始', '没有可用网卡。请安装 Npcap 后重启程序。'); return
        try:
            conf.use_pcap = True
            if not conf.use_pcap: raise RuntimeError('无法加载 Npcap/libpcap')
            # Reload interfaces after switching to the libpcap backend.
            conf.ifaces.reload()
            iface = self.ifaces[self.interface.current()].name
            bpf = self.bpf.get().strip()
            self.generation += 1
            generation = self.generation
            def receive(packet):
                try: self.q.put_nowait((generation, packet))
                except queue.Full: self.dropped += 1
            self.sniffer = AsyncSniffer(iface=iface, filter=bpf or None, store=False, prn=receive,
                                        started_callback=lambda: self.q.put(('started', generation)))
            self.sniffer.start()
            self.running = True; self.start_btn.config(state='disabled'); self.stop_btn.config(state='normal')
            self.status.set('正在启动抓包…')
        except Exception as e: messagebox.showerror('启动失败', str(e))

    def stop(self):
        if self.sniffer:
            try:
                if self.sniffer.running: self.sniffer.stop()
                self.sniffer.join(timeout=2)
            except Exception: pass
        self.running = False; self.start_btn.config(state='normal'); self.stop_btn.config(state='disabled')
        self.status.set(f'已停止 | 数据包 {len(self.packets)} | 队列丢弃 {self.dropped}')

    def poll(self):
        for _ in range(300):
            try: generation, p = self.q.get_nowait()
            except queue.Empty: break
            if generation == 'started': continue
            if generation != self.generation: continue
            if len(self.packets) < LIMIT:
                self.packets.append(p)
                if matches(p, self.filter.get()): self.insert(len(self.packets)-1, p)
            else: self.dropped += 1
        if self.running:
            if self.sniffer and self.sniffer.thread and not self.sniffer.thread.is_alive():
                error = getattr(self.sniffer, 'exception', None)
                self.stop(); messagebox.showerror('抓包失败', f'{error or "抓包线程已退出"}\n请检查 Npcap、权限、网卡和 BPF 表达式。')
            else: self.status.set(f'抓包中 | 数据包 {len(self.packets)} | 队列/上限丢弃 {self.dropped}')
        self.root.after(100, self.poll)

    def insert(self, i, p):
        src,dst = endpoints(p)
        t = datetime.datetime.fromtimestamp(float(p.time)).strftime('%H:%M:%S.%f')[:-3]
        self.tree.insert('', 'end', iid=str(i), values=(i+1,t,src,dst,protocol(p),len(p),p.summary()), tags=('even',) if i % 2 == 0 else ())

    def rebuild(self):
        self.tree.delete(*self.tree.get_children())
        for i,p in enumerate(self.packets):
            if matches(p, self.filter.get()): self.insert(i,p)

    def select(self, event=None):
        selected = self.tree.selection()
        if not selected: return
        p = self.packets[int(selected[0])]
        self.details.delete('1.0','end'); self.details.insert('1.0', p.show(dump=True))
        data = bytes(p)
        lines = [f'{i:04x}  ' + ' '.join(f'{b:02x}' for b in data[i:i+16]).ljust(47) + '  ' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16]) for i in range(0,len(data),16)]
        self.hex.delete('1.0','end'); self.hex.insert('1.0','\n'.join(lines))

    def clear(self):
        self.generation += 1
        # Existing capture callback uses its original generation; clearing while capturing would discard future packets.
        if self.running:
            self.generation -= 1
            while True:
                try: self.q.get_nowait()
                except queue.Empty: break
        self.packets.clear(); self.dropped=0; self.rebuild()
        self.details.delete('1.0','end'); self.hex.delete('1.0','end')

    def open_file(self):
        if self.running: messagebox.showinfo('提示','请先停止抓包。'); return
        path = filedialog.askopenfilename(filetypes=[('抓包文件','*.pcap *.pcapng'),('所有文件','*.*')])
        if not path: return
        try:
            packets = rdpcap(path, count=LIMIT+1)
            self.clear(); self.packets = list(packets[:LIMIT]); self.rebuild()
            self.status.set(f'已打开 {path} | {len(self.packets)} 包' + (' | 超出上限的包未载入' if len(packets)>LIMIT else ''))
        except Exception as e: messagebox.showerror('读取失败', str(e))

    def save_file(self):
        if not self.packets: messagebox.showinfo('提示','没有可保存的数据包。'); return
        path = filedialog.asksaveasfilename(defaultextension='.pcap', filetypes=[('PCAP 文件','*.pcap')])
        if path:
            try: wrpcap(path,self.packets); self.status.set(f'已保存 {len(self.packets)} 包至 {path}')
            except Exception as e: messagebox.showerror('保存失败',str(e))

    def show_flow(self):
        selected = self.tree.selection()
        if not selected: messagebox.showinfo('提示','请先选择一个 TCP 数据包。'); return
        key = flow_key(self.packets[int(selected[0])])
        if key is None: messagebox.showinfo('提示','选中的包不是 TCP/IP。'); return
        win = tk.Toplevel(self.root); win.title('TCP 流：按捕获顺序展示载荷'); win.geometry('900x600')
        text = tk.Text(win, wrap='word', font=('Consolas',10)); text.pack(fill='both',expand=True)
        text.insert('end', f'{key[0]} ↔ {key[1]}\n按抓包顺序显示，不进行 TCP 重组或去重；TLS 内容通常为密文。\n\n')
        for i,p in enumerate(self.packets):
            if flow_key(p)==key and Raw in p:
                src,dst=endpoints(p); payload=bytes(p[Raw].load)
                text.insert('end',f'--- #{i+1} {src}:{p[TCP].sport} → {dst}:{p[TCP].dport} ({len(payload)} 字节) ---\n')
                text.insert('end',payload.decode('utf-8',errors='replace')+'\n')
        text.config(state='disabled')

    def close(self):
        if self.running: self.stop()
        self.root.destroy()


if __name__ == '__main__':
    App(tk.Tk()).root.mainloop()
