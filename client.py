import sys
import socket
import os
import ssl
import threading
from PyQt5 import QtWidgets, QtCore  # pyqt5
from windows import Ui_Form  # gui 引入我寫的interface
from crypto import generate_rsa_key, save_private_key, save_public_key, load_private_key, load_public_key, decrypt_aes_key, decrypt_file, generate_aes_key, encrypt_aes_key, encrypt_file
server_address = ('127.0.0.1', 1234)
client_address = ('127.0.0.1', 4321)
ports_list = [1111, 2222, 3333, 4444]  # 為了廣播建立的list
file_name = None  # 檔案
client_aes_key = None
try:
    client_private_key = load_private_key('client_private_key.pem')
    client_public_key = load_public_key('client_public_key.pem')
    print("Loaded existing RSA keys...")
except FileNotFoundError:  # 每檔案就生成一對
    client_private_key, client_public_key = generate_rsa_key()
    save_private_key(client_private_key, 'client_private_key.pem')
    save_public_key(client_public_key, 'client_public_key.pem')
    print("Generating new RSA keys...")
server_public_key = load_public_key(
    'server_public_key.pem')  # 假設有收到server的public-key


class MyWindow(QtWidgets.QWidget, Ui_Form):
    recv_signal = QtCore.pyqtSignal(str)  # 定義一個信號
    recv_status_signal = QtCore.pyqtSignal(str)  # 定義另一個信號（狀態燈）

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(
            lambda: choose_file(self, self.textBrowser))
        self.pushButton_2.clicked.connect(
            lambda: self.confirm_send())
        self.pushButton_3.clicked.connect(
            lambda: self.saveas_file())
        self.pushButton_4.clicked.connect(
            lambda: self.clear_file())
        # 連接信號到update_text_browser
        self.recv_signal.connect(self.update_text_browser)
        self.recv_status_signal.connect(self.update_light)  # 連接信號到update_light
        status_thread = threading.Thread(target=recv_status, args=(self,))
        status_thread.daemon = True  # 測試守護thread
        status_thread.start()
    # --------------------更新的燈---------------------------------------

    def update_light(self, status):
        if status == "red":
            self.label_3.setStyleSheet("background-color: rgb(255,0,0);\n"
                                       "min-width:16px;\n"
                                       "min-height:16px;\n"
                                       "max-width:16px;\n"
                                       "max-height:16px;\n"
                                       "border:1px solid black;\n"
                                       "border-radius: 8px;")
        elif status == "green":
            self.label_3.setStyleSheet("background-color:  rgb(0,255,0);\n"
                                       "min-width:16px;\n"
                                       "min-height:16px;\n"
                                       "max-width:16px;\n"
                                       "max-height:16px;\n"
                                       "border:1px solid black;\n"
                                       "border-radius: 8px;")

    def confirm_send(self):  # 寄送前彈出消息讓你選擇取消或是ok
        msg_box = QtWidgets.QMessageBox(self)
        msg_box.setWindowTitle('Confirm Send')
        msg_box.setText(
            'Are you sure you want to send the file to the server?')
        msg_box.setStandardButtons(
            QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel)
        msg_box.setDefaultButton(QtWidgets.QMessageBox.Ok)
        msg_box.setStyleSheet("""
            QLabel{ color: black;}
            QPushButton {
            color: black;} 
            """)
        reply = msg_box.exec_()
        if reply == QtWidgets.QMessageBox.Ok:
            self.send_file_123()
    # -------------------出現在下面顯示的文字------------------

    def update_text_browser(self, text):
        self.textBrowser.append(text)

    # ---------開啟一個收到檔案的thread-----------
    def send_file_123(self):
        send_file(file_name, server_address, self.textBrowser)
        recv_thread = threading.Thread(target=recv_server, args=(self,))
        recv_thread.daemon = True  # 測試一下守護thread
        recv_thread.start()

    # ----------------點選清除頁面上的字-----------------------------------
    def clear_file(self):
        global file_name
        file_name = None
        self.textBrowser.clear()
        self.textBrowser.setPlainText("File selection cleared.")
    # ----------------結果儲存檔案(txt)-----------------------------------

    def saveas_file(self):
        text = self.textBrowser.toPlainText()
        if not text:
            return
        save_filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'Save file as', '', 'Text Files (*.txt);;All Files (*)')
        if save_filename:
            with open(save_filename, 'w') as file:
                file.write(text)
            self.textBrowser.append(f"File saved as {save_filename}")

# ----------------------選擇檔案---------------------------


def choose_file(window, resultText):
    global file_name
    file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
        window, 'Open file', '', 'Python Files (*.py);;All Files (*)')  # 選擇檔案，只選擇.py
    if not file_name:
        return
    resultText.setPlainText(f"Selected file: {file_name}")

# ----------------------寄送檔案到server---------------------------


def send_file(file, address, resultText):
    if not file:
        return
    print(file)
    try:
        aes_key = generate_aes_key()  # 首先先生成一個aes的key
        encrypted_aes_key = encrypt_aes_key(
            aes_key, server_public_key)  # 用公鑰把aes_key加密
        encrypted_file = encrypt_file(
            file, aes_key)  # 將檔案用aes_key加密
        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp連線
        sd.connect(server_address)
        sd.sendall(encrypted_aes_key)  # 寄送被公鑰加密的aes_key

        # ---------------------我想要做到一塊一塊的送出--------------
        offset = 0
        while offset < len(encrypted_file):
            chunk = encrypted_file[offset:offset+1024]  # 提取每一塊結果
            sd.sendall(chunk)  # 寄送
            offset += len(chunk)  # 主要是為了計算看有沒有傳完
            print(f"Sent: {len(chunk)}")
        print(f"File {file} sent successfully.")
    except Exception as e:
        print(f"Failed to send file: {e}")
    finally:
        sd.close()  # 寄送完就關掉

# ---------------------處理接收到的aes-key-------------------------------


def receive_aes_key(conn):
    try:
        encrypted_aes_key = conn.recv(256)
        aes_key = decrypt_aes_key(encrypted_aes_key, client_private_key)
        return aes_key
    except Exception as e:
        print(f"Failed to  AES key: {e}")
        return None


# ----------------------從server收到分析報告-----------------------
def recv_server(window):
    global client_aes_key
    print("Waiting for server send!!!")
    window.recv_signal.emit("Waiting for server send!!!")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sd:  # tcp連線
        sd.bind(client_address)
        sd.listen()
        conn, addr = sd.accept()
        print(f"Connected to {addr}")
        client_aes_key = receive_aes_key(conn)
        window.recv_signal.emit(f"Connected to {addr}")
        encrypted_file = b""  # 存加密的檔案
        while True:
            rec_data = conn.recv(1024)
            if not rec_data:
                break
            encrypted_file += rec_data  # 將收到的資料分段放到儲放的檔案裡面
        decrypted_file = decrypt_file(encrypted_file, client_aes_key)
        window.recv_signal.emit("File received successfully.")
        window.recv_signal.emit(
            f"Analysis Result:\n{decrypted_file.decode('utf-8')}")
        conn.close()

# ----------------------收到廣播的信號燈---------------------------


def recv_status(window):
    while True:
        try:
            broadcast_ports = ports_list[0]  # 開始先挑第一個元素，如果bind相同就會捕獲錯誤資訊
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rec_sd:
                rec_sd.setsockopt(socket.SOL_SOCKET,
                                  socket.SO_REUSEADDR, 1)  # 讓我可以趕快用位址
                rec_sd.setsockopt(socket.SOL_SOCKET,
                                  socket.SO_BROADCAST, 1)  # 設置廣播
                rec_sd.bind(('127.0.0.1', broadcast_ports))
                while True:
                    try:
                        data, _ = rec_sd.recvfrom(1024)  # 收到廣播資訊
                        status_message = data.decode()
                        print(status_message)
                        if "red" in status_message:  # 根據接收到的消息判斷狀態
                            window.recv_status_signal.emit("red")
                        elif "green" in status_message:
                            window.recv_status_signal.emit("green")
                    except Exception as e:
                        print(f"Failed to receive status: {e}")
        except OSError:
            ports_list.pop(0)  # 如果捕獲到OSError的事件，就刪除那個port
            continue


def main():
    app = QtWidgets.QApplication(sys.argv)  # 視窗程式開始
    window = MyWindow()  # 創建基底元素
    window.show()  # 顯示主窗口
    sys.exit(app.exec_())  # 視窗程式結束


if __name__ == "__main__":
    main()
