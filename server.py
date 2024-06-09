import socket
import subprocess  # 可以執行外部命令的一個module
import threading
import time
from crypto import generate_rsa_key, save_private_key, save_public_key, load_private_key, load_public_key, decrypt_aes_key, decrypt_file, generate_aes_key, encrypt_aes_key, encrypt_file

server_address = ('127.0.0.1', 1234)
client_address = ('127.0.0.1', 4321)
broadcast_port = [1111, 2222, 3333, 4444]  # 廣播用的port
client_list = []  # 記錄連線的客戶端表
maxclient = 3   # 最大的客戶端
status = "green"  # 剛開始的狀態燈
# -------------------------初始化private-key與public-key----------------------
try:
    server_private_key = load_private_key('server_private_key.pem')
    server_public_key = load_public_key('server_public_key.pem')
    print("Loaded existing RSA keys...")
except FileNotFoundError:  # 每檔案就生成一對
    server_private_key, server_public_key = generate_rsa_key()
    save_private_key(server_private_key, 'server_private_key.pem')
    save_public_key(server_public_key, 'server_public_key.pem')
    print("Generating new RSA keys...")
client_public_key = load_public_key(
    'client_public_key.pem')  # 假設收到client public_key
# ---------------------處理接收到的aes-key-------------------------------


def receive_aes_key(conn):
    try:
        encrypted_aes_key = conn.recv(256)
        aes_key = decrypt_aes_key(encrypted_aes_key, server_private_key)
        return aes_key
    except Exception as e:
        print(f"Failed to  AES key: {e}")
        return None

# ----------------------收到檔案處理---------------------------


def recv_file(conn, addr, aes_key):
    print(f"Connected to {addr}")
    encrypted_file = b""  # 存加密的檔案
    while True:
        rec_data = conn.recv(1024)
        if not rec_data:
            break
        encrypted_file += rec_data  # 將收到的資料分段放到儲放的檔案裡面
    decrypted_file = decrypt_file(encrypted_file, aes_key)  # 將加密的檔案用aes_key解密

    with open("output.py", "wb") as file:
        file.write(decrypted_file)  # 將檔案寫到output.py

    analyze_res = subprocess.run(
        ['bandit', '-r', "output.py"], capture_output=True, text=True)  # 利用bandit分析
    if analyze_res:
        threading.Thread(target=send_analysis_result,
                         args=(analyze_res.stdout,)).start()  # 開啟寄送檔案結果的thread
    else:
        print("Analysis failed")

# ----------------------寄送分析結果---------------------------


def send_analysis_result(result):
    global client_aes_key
    try:
        client_aes_key = generate_aes_key()  # 首先先生成一個aes的key
        encrypted_aes_key = encrypt_aes_key(
            client_aes_key, client_public_key)  # 用公鑰把aes_key加密
        encrypted_file = encrypt_file(
            result, client_aes_key)  # 將檔案用aes_key加密
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # tcp連線
        sock.connect(client_address)
        sock.sendall(encrypted_aes_key)  # 寄送被公鑰加密的aes_key

        # ---------------------我想要做到一塊一塊的送出--------------
        offset = 0
        while offset < len(encrypted_file):
            chunk = encrypted_file[offset:offset+1024]  # 提取每一塊結果
            sock.sendall(chunk)  # 寄送
            offset += len(chunk)  # 主要是為了計算看有沒有傳完
            print(f"Sent: {len(chunk)}")
    except Exception as e:
        print(f"Failed to send analysis result: {e}")
    finally:
        sock.close()
# ----------------------廣播現在狀態---------------------------


def broadcast_status():
    global status
    while True:
        try:
            broadcast_sd = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM)  # udp方式
            broadcast_sd.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 重用地址
            broadcast_sd.setsockopt(
                socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # 開啟廣播設定
            for ports in broadcast_port:
                # 每一輪對所有port發送status
                broadcast_sd.sendto(status.encode(), ('127.0.0.1', ports,))
            time.sleep(1)
        except Exception as e:
            print(f"Failed to broadcast status: {e}")


# ---------------------------主函式---------------------------


def main():
    global status
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sd:
        sd.bind(server_address)
        sd.listen()
        print("Server is listening...")
        threading.Thread(target=broadcast_status).start()  # 開啟廣播thread
        while True:
            conn, addr = sd.accept()
            if len(client_list) >= maxclient:  # 當連接數量超過限制時拒絕新的連接
                status = "red"
                time.sleep(1)
                conn.close()
            else:
                status = "green"
                client_list.append(conn)  # 新加入就放到客戶端表裡面
                aes_key = receive_aes_key(conn)  # 先處理收到的aes_key
                threading.Thread(target=recv_file, args=(
                    conn, addr, aes_key)).start()  # 開啟收到檔案的thread


if __name__ == "__main__":
    main()
