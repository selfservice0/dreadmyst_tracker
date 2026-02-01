import socket
import time
import threading
import sys

# ========================== CONFIG ==========================
HOST = "148.113.218.141"
PORT = 16383

# === UPDATE THESE EVERY TIME YOU LOG IN MANUALLY ===
# (Tokens expire — capture fresh login packet each session)
LOGIN_PAYLOAD = bytes.fromhex(
    "6800000002003364643061373135396435303363613165363538666361323763636631"
    "3731643738393036663333333964643530313165363531343034733234663930336430"
    "00bf040000643235313734333731393934636566313731653562326335643637313333"
    "333000"
)

# Use the most recent working character select packet you captured
SELECT_PAYLOAD = bytes.fromhex(
    "6800000002003364643061373135396435303363613165363538666361323763636631"
    "3731643738393036663333333964643530313165363531343034373332346639303364"
    "00bf040000643235313734333731393934636566313731653562326335643637313333"
    "333000"
)

# Heartbeats
HEARTBEAT_1 = bytes.fromhex("06000000050000420000")   # type 6
HEARTBEAT_2 = bytes.fromhex("0a0000000100943752b2e7f00100")  # type 0A

# ============================================================

def send_heartbeats(sock):
    i = 0
    while True:
        time.sleep(25 + (i % 11))  # 25-35s variation
        try:
            if i % 2 == 0:
                sock.send(HEARTBEAT_1)
                print("[💓] Heartbeat type 06 sent")
            else:
                sock.send(HEARTBEAT_2)
                print("[💓] Heartbeat type 0A sent")
            i += 1
        except:
            break

def main():
    print("Ghost Chat Sniffer v2 - Ready")
    while True:
        sock = None
        try:
            print("\n🔌 Connecting...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(12)
            sock.connect((HOST, PORT))
            print("✅ Connected")

            print("🔑 Sending login/auth...")
            sock.send(LOGIN_PAYLOAD)

            print("📥 Waiting for server response (profile sync)...")
            buffer = b""
            start = time.time()
            synced = False

            while time.time() - start < 12:
                try:
                    data = sock.recv(8192)
                    if not data:
                        print("❌ Server closed connection (likely invalid token)")
                        break
                    buffer += data
                    print(f"   Received {len(data)} bytes (total: {len(buffer)})")

                    # Detect successful sync
                    if len(buffer) > 1200 or b"Swiftx" in data or b"Catholic Church" in data:
                        synced = True
                        print("✅ Profile sync detected!")
                        break
                except socket.timeout:
                    print("⏱️ Timeout waiting for sync")
                    break
                except Exception as e:
                    print(f"Recv error: {e}")
                    break

            if not synced:
                print("⚠️  Failed to get profile sync (most likely expired login token)")
                print("   → Capture a fresh login packet and update LOGIN_PAYLOAD")
                sock.close()
                time.sleep(10)
                continue

            print("🎮 Sending character select...")
            sock.send(SELECT_PAYLOAD)

            print("❤️  Starting heartbeat thread...")
            threading.Thread(target=send_heartbeats, args=(sock,), daemon=True).start()

            print("\n👂 Listening for chat / item links...\n")
            while True:
                data = sock.recv(8192)
                if not data:
                    print("❌ Server disconnected")
                    break

                # Show anything that might be chat
                try:
                    text = data.decode('utf-8', errors='ignore').strip()
                    if len(text) > 4 and any(c.isprintable() and not c.isspace() for c in text):
                        if '[' in text or ']' in text or 'http' in text:
                            print(f"🔗 [ITEM LINK] {text[:500]}")
                        else:
                            print(f"💬 [CHAT] {text[:500]}")
                except:
                    pass

                # Show hex preview if it contains printable chars
                if any(32 <= b <= 126 for b in data[:60]):
                    print(f"📦 [Binary packet] {data.hex()[:120]}...")

        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            print("🔄 Reconnecting in 10 seconds...")
            time.sleep(10)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Stopped by user.")