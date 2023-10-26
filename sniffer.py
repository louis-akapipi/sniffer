# GUI绘制相关库
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
# 抓包相关库
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


def timestamp2Time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime('%Y-%m-%d %H:%M:%S', time_array)
    return mytime


def clickParcketList(event):
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree
    parse_tree.delete(*parse_tree.get_children())
    # 设置协议解析区的宽度
    parse_tree.column('Dissect', width=list_frame.winfo_width())
    packet_num = int(selected_item[0]) - 1
    # 取出要分析的数据包
    packetCaptured = packet_list[packet_num]
    lines = (packetCaptured.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = parse_tree.insert('', 'end', text=line)
        else:
            parse_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 动态调整协议解析区的宽度
        if parse_tree.column('Dissect', width=None) < col_width:
            parse_tree.column('Dissect', width=col_width)

    if IP in packetCaptured:
        ip = packetCaptured[IP]
        ip_chksum = ip.chksum
        ip.chksum = None
        ip_check = IP(raw(ip)).chksum
        ip.chksum = ip_chksum

        if TCP in packetCaptured:
            tcp = packetCaptured[TCP]
            tcp_chksum = tcp.chksum
            tcp.chksum = None
            tcp_check = TCP(raw(tcp)).chksum
            tcp.chksum = tcp_chksum

            information = "IP与TCP的校验和检查通过\r\nIP的校验和为：{chksum_ip}\r\nTCP的检验和为：" \
                          "{chksum_tcp}".format(chksum_ip=ip_chksum, chksum_tcp=tcp_chksum)

            if ip_check == ip_chksum and tcp_check == tcp_chksum:
                tkinter.messagebox.showinfo("检查校验和", information)
            else:
                tkinter.messagebox.showerror("错误警告", "IP或TCP的校验和出错")
        elif UDP in packetCaptured:
            udp = packetCaptured[UDP]
            udp_chksum = udp.chksum
            udp.chksum = None
            # 重新计算数据包的校验和
            udp_check = UDP(raw(udp)).chksum
            udp.chksum = udp_chksum

            information = "IP与UDP的校验和检查通过\r\nIP的校验和为：" \
                          "{chksum_ip}\r\nUDP的检验和为：{chksum_udp}".format(chksum_ip=ip_chksum, chksum_udp=udp_chksum)

            if ip_check == ip_chksum and udp_check == udp_chksum:
                tkinter.messagebox.showinfo("校验和的检查", information)
            else:
                tkinter.messagebox.showerror("校验和错误警告", "IP或UDP的校验和出错")

    # 使用十六进制显示数据包具体内容
    hexdump_scrolledtext.config(state=NORMAL)
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packetCaptured, dump=True))
    hexdump_scrolledtext.config(state=DISABLED)


# 设置过滤条件
def capturePacket():
    # 获得过滤条件
    filters = filter_entry.get()
    stop_sending.clear()
    global packet_list
    # 刷新
    packet_list.clear()
    sniff(filter=filters, prn=(lambda x: parsePacket(x)), stop_filter=(lambda x: stop_sending.is_set()))


# 对数据包进行处理和分析
def parsePacket(subPacket):
    if not pause_flag:
        global packet_list
        packet_list.append(subPacket)

        packet_time = timestamp2Time(subPacket.time)
        src = subPacket[Ether].src
        dst = subPacket[Ether].dst
        type = subPacket[Ether].type
        protocols = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891DD: 'TTE'}
        if type in protocols:
            proto = protocols[type]
        else:
            proto = 'LOOP'

        if proto == 'IPv4':
            protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89: 'OSPF'}
            src = subPacket[IP].src
            dst = subPacket[IP].dst
            proto = subPacket[IP].proto
            if proto in protos:
                proto = protos[proto]

        if TCP in subPacket:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = subPacket[TCP].sport
            dport = subPacket[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]

        if UDP in subPacket:
            if subPacket[UDP].sport == 53 or subPacket[UDP].dport == 53:
                proto = 'DNs'

        length = len(subPacket)
        info = subPacket.summary()
        global packet_id
        list_tree.insert('', 'end', packet_id, text=packet_id, values=(packet_id, packet_time, src, dst, proto, length, info))
        list_tree.update_idletasks()
        packet_id = packet_id + 1


# 将抓取的数据包保存为.pcap文件
def saveData():
    global save_flag
    save_flag = True
    filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'), ('数据包', '.pcap')], initialfile='save.pcap')
    if filename.find('.pcap') == -1:
        filename = filename + '.pcap'
    wrpcap(filename, packet_list)


# 开始抓包
def start():
    global pause_flag, stop_flag, save_flag
    if stop_flag is True and save_flag is False:
        result = tkinter.messagebox.askyesnocancel('提醒', '是否保存抓到的数据')
        if result:
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'), ('数据包', '.pcap')], initialfile='save.pcap')
            if filename.find('.pcap') == -1:
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
        else:
            stop_flag = False
            return

    start_btn.config(state=DISABLED)
    save_btn.config(state=DISABLED)
    pause_btn.config(state=NORMAL)
    stop_btn.config(state=NORMAL)

    stop_flag = False

    if not pause_flag:
        items = list_tree.get_children()
        for item in items:
            list_tree.delete(item)
        list_tree.clipboard_clear()
        global packet_id
        packet_id = 1

        t = threading.Thread(target=capturePacket)
        # 不等待子进程，直接关闭
        t.setDaemon(True)
        t.start()
        save_flag = False
    else:
        pause_flag = False


# 暂停抓包
def pause():
    start_btn.config(state=NORMAL)
    pause_btn.config(state=DISABLED)
    global pause_flag
    pause_flag = True


# 停止抓包
def stop():
    global pause_flag, stop_flag
    stop_sending.set()
    start_btn.config(state=NORMAL)
    save_btn.config(state=NORMAL)

    pause_btn.config(state=DISABLED)
    stop_btn.config(state=DISABLED)

    pause_flag = False
    stop_flag = True


# 退出程序
def quitCapture():
    stop_sending.set()
    if save_flag is False:
        result = tkinter.messagebox.askyesnocancel('提醒', '是否保存抓到的数据包')
        if result is True:
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'), ('数据包', '.pcap')], initialfile='save.pcap')
            if filename.find('.pcap') == -1:
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
            tk.destroy()
        elif result is False:
            # 直接退出
            tk.destroy()
    else:
        tk.destroy()


if __name__ == '__main__':
    # 全局变量声明
    stop_sending = threading.Event()
    packet_id = 1
    packet_list = []
    pause_flag = False
    save_flag = False
    stop_flag = False

    # 初始化界面
    tk = tkinter.Tk()
    # 设置标题、大小、图标
    tk.title('DukeFishron')
    tk.geometry('900x700')
    tk.iconphoto(False, tkinter.PhotoImage(file='DukeFishron.png'))
    main_window = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

    # 设置按钮及初始状态
    menubar = Frame(tk)
    start_btn = Button(menubar, width=10, text='开始', state=NORMAL, command=start)
    pause_btn = Button(menubar, width=10, text='暂停', state=DISABLED, command=pause)
    stop_btn = Button(menubar, width=10, text='停止', state=DISABLED, command=stop)
    save_btn = Button(menubar, width=10, text='保存', state=DISABLED, command=saveData)
    quit_btn = Button(menubar, width=10, text='退出', state=NORMAL, command=quitCapture)

    filter_label = Label(menubar, width=10, text='过滤器：')
    filter_entry = Entry(menubar)

    # 数据包列表
    list_frame = Frame()
    list_sub_frame = Frame(list_frame)
    list_tree = Treeview(list_sub_frame, selectmode=BROWSE)
    list_tree.bind('<<TreeviewSelect>>', clickParcketList)
    # 垂直滚动条
    list_yscrollbar = Scrollbar(list_sub_frame, orient=VERTICAL, command=list_tree.yview)
    list_tree.config(yscrollcommand=list_yscrollbar.set)

    # 水平
    list_xscrollbar = Scrollbar(list_frame, orient=HORIZONTAL, command=list_tree.xview)
    list_tree.config(xscrollcommand=list_xscrollbar.set)
    # 列标题
    list_tree['columns'] = ('NO.', 'Time', 'Source', 'Dextination', 'Protocol', 'Length', 'Info')
    list_column_width = [100, 180, 160, 160, 100, 100, 600]
    list_tree['show'] = 'headings'
    for column_name, column_width in zip(list_tree['columns'], list_column_width):
        list_tree.column(column_name, width=column_width, anchor='w')
        list_tree.heading(column_name, text=column_name)

    # 协议解析区
    parse_frame = Frame()
    parse_sub_frame = Frame(parse_frame)
    parse_tree = Treeview(parse_sub_frame, selectmode=BROWSE)
    parse_tree["columns"] = ("Dissect",)
    parse_tree.column('Dissect', anchor='w')
    parse_tree.heading('#0', text='Packet Dissection', anchor='w')

    parse_yscrollbar = Scrollbar(parse_sub_frame, orient=VERTICAL, command=list_tree.yview)
    parse_tree.config(yscrollcommand=parse_yscrollbar.set)

    # 水平
    parse_xscrollbar = Scrollbar(parse_frame, orient=HORIZONTAL, command=parse_tree.xview)
    parse_tree.config(xscrollcommand=parse_xscrollbar.set)

    # 16进制分析区
    hexdump_scrolledtext = ScrolledText()
    hexdump_scrolledtext.config(state=DISABLED)

    # 布局
    start_btn.pack(side=LEFT)
    pause_btn.pack(side=LEFT, after=start_btn, padx=5)
    stop_btn.pack(side=LEFT, after=pause_btn, padx=5)
    save_btn.pack(side=LEFT, after=stop_btn, padx=5)
    quit_btn.pack(side=LEFT, after=save_btn, padx=5)

    filter_label.pack(side=LEFT, after=quit_btn)
    filter_entry.pack(side=LEFT, after=filter_label, fill=X)
    menubar.pack(side=TOP, fill=X)

    list_tree.pack(side=LEFT, fill=X, expand=YES)
    list_frame.pack(side=TOP, fill=X, expand=YES, anchor='n')
    list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    list_xscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    list_yscrollbar.pack(side=RIGHT, fill=Y, expand=YES)

    parse_tree.pack(side=LEFT, fill=X, expand=YES)
    parse_frame.pack(side=TOP, fill=X, expand=YES, anchor='n')
    parse_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
    parse_xscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
    parse_yscrollbar.pack(side=RIGHT, fill=Y, expand=YES)

    main_window.add(list_frame)
    main_window.add(parse_frame)
    main_window.add(hexdump_scrolledtext)
    main_window.pack(fill=BOTH, expand=1)
    # 关闭提醒
    tk.protocol('WM_DELETE_WINDOW', quitCapture)

    tk.mainloop()
