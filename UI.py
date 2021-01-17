import tkinter as tk
from tkinter import *
from tkinter import messagebox
from PEKS import *
import json


class Window(object):

    def __init__(self):
        root = tk.Tk()
        root.minsize(580, 320)  # 窗口大小
        root.resizable(width=False, height=False)  # False窗口大小不可变

        root.title('PEKSBoneh2004')  # 窗口标题

        label1 = Label(text='关键字：')  # 标签
        label1.place(x=10, y=10, width=80, height=25)  # 确定位置

        self.line_text = Entry(root)  # 单行文本输入
        self.line_text.place(x=80, y=10, width=420, height=25)

        button = Button(text='开始查询', command=self.inquiry)  # 按钮
        button.place(x=500, y=10, width=60, height=25)

        label2 = Label(text='查询结果:')
        label2.place(x=10, y=100, width=80, height=20)
        self.text = Text(root)  # 多行文本显示
        self.text.place(x=80, y=50, width=480, height=240)

        root.mainloop()  # 主循环

    '''查询'''

    def inquiry(self):
        keyword = self.line_text.get()  # 获取输入的内容
        self.text.delete(1.0, tk.END)  # 用于删除后续显示的文件
        if not keyword:  # 没有输入句子就查询，会出现弹窗警告
            messagebox.showinfo("Warning", '请先输入需要查询的关键字!')
        else:
            # CA生成公共参数、公钥、私钥。公钥分配给DO，私钥分配给DU
            [params, g, sk, pk] = KeyGen(512, 160)

            # DO拥有的数据，文件和关键字的对应关系为多对多
            with open('word.json', 'r', encoding='utf8')as fp:
                message = json.load(fp)
            # message = {'<text1>': ['word1', 'word2'], '<text2>': ['word3', ], '<text3>': ['word1', ]}

            n = 0
            cipher = {}
            for key in message:
                for i in list(message[key]):
                    # DO通过CA分发的PK将关键字word上传至CSP
                    cipher[n] = PEKS(params, g, pk, i)
                    n = n + 1

            # DU通过单项陷门函数，通过SK和word生成陷门td
            td = Trapdoor(params, sk, keyword)
            for key in cipher:

                # CSP接收到陷门td，与服务器中已加密的关键字比较
                B = Test(params, pk, cipher[key], td)
                infos = []
                # 若检索到关键字，则将该关键字对应的文件发送给DU
                if B:
                    print("在密文中检索到关键字%s" % keyword)
                    infos.append(f'查找到对应关键字：{keyword}\n')
                    num = 0
                    for key in message:
                        for i in list(message[key]):
                            if i == keyword:
                                infos.append(f"file: {key}\n")
                                num = num + 1
                    infos.append(f'共 {num}个文件\n')
                    # 查找到的内容插入文本，并显示
                    self.text.insert('insert', '\n'.join(infos)[:-1])
                    break
            if len(infos) == 0:
                self.text.insert('insert', '\n未找到关键字')


if __name__ == '__main__':
    Window()
