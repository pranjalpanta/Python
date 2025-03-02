from tkinter import ttk
import tkinter.messagebox as messagebox
import requests
import socket
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog
import nmap
import subprocess
import os

# Global variable for file path
file_path = ""

def save_output():
    content = output_field.get("1.0", tk.END)
    filename = tk.filedialog.asksaveasfilename(
        initialdir="/home/kali/Desktop/WebEnumerationfile",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if filename:
        with open(filename, "w") as f:
            f.write(content)

def start_gather_info():
    url = url_entry.get() or "http://testphp.vulnweb.com/"
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        output_field_info.delete("1.0", tk.END)
        output_field_info.insert(tk.END, f"Status code: {response.status_code}\n")
        
        server = response.headers.get('Server')
        if server:
            output_field_info.insert(tk.END, f"Server: {server}\n")
        
        technologies = response.headers.get('X-Powered-By')
        if technologies:
            output_field_info.insert(tk.END, f"Technologies: {technologies}\n")
        
        title = soup.find('title')
        if title:
            output_field_info.insert(tk.END, f"Title: {title.text}\n")
        
        links = soup.find_all('a')
        output_field_info.insert(tk.END, f"Number of links: {len(links)}\n")
        
        forms = soup.find_all('form')
        for form in forms:
            output_field_info.insert(tk.END, f"Form name: {form.get('name')}\n")
            output_field_info.insert(tk.END, f"Form action: {form.get('action')}\n")
            inputs = form.find_all('input')
            output_field_info.insert(tk.END, f"Number of input fields in form {form.get('name')}: {len(inputs)}\n")
        
        images = soup.find_all('img')
        for image in images:
            output_field_info.insert(tk.END, f"Image URL: {image['src']}\n")
        
        output_field_info.insert(tk.END, f"Headers: {response.headers}\n")
        
        try:
            scanner = nmap.PortScanner()
            target_host = "testphp.vulnweb.com"
            target_ports = "1-1000"
            result = scanner.scan(target_host, target_ports)
            
            output_field_info.insert(tk.END, f"\nPort Scan Results for {target_host}:\n")
            for host in result["scan"]:
                for port in result["scan"][host]["tcp"]:
                    state = result["scan"][host]["tcp"][port]["state"]
                    output_field_info.insert(tk.END, f"Port {port}: {state}\n")
        except Exception as e:
            output_field_info.insert(tk.END, f"Port scan error: {str(e)}\n")
            
    except requests.RequestException as e:
        output_field_info.insert(tk.END, f"Error fetching URL: {str(e)}\n")

def scan_directories(url, directories):
    directories_dont_exist = []
    try:
        response = requests.get(url)
        for directory in directories:
            try:
                response = requests.get(f'{url}/{directory}')
                if response.status_code == 200:
                    output_field.insert(tk.END, f'{url}/{directory} exists\n')
                else:
                    output_field.insert(tk.END, f'{url}/{directory} doesn\'t exist\n')
                    directories_dont_exist.append(directory)
            except requests.RequestException:
                output_field.insert(tk.END, f'Error accessing {url}/{directory}\n')
    except socket.gaierror:
        output_field.insert(tk.END, f'Unable to resolve the hostname of {url}\n')
    except requests.RequestException as e:
        output_field.insert(tk.END, f'Error connecting to {url}: {str(e)}\n')

def read_directory_list(directory):
    try:
        with open(directory, 'r') as f:
            directories = f.read().splitlines()
        return directories
    except FileNotFoundError:
        output_field.insert(tk.END, f'{directory} does not exist\n')
        return []
    except Exception as e:
        output_field.insert(tk.END, f'Error reading directory file: {str(e)}\n')
        return []

def browse_file():
    global file_path
    file_path = filedialog.askopenfilename(
        initialdir="/home/kali/Desktop/WebEnumerationfile",
        filetypes=[("Text Files", "*.txt")]
    )
    if file_path:
        print(file_path)
    return file_path

def check_directories(file_path):
    url = ip_address_entry.get()
    if not url:
        output_field.insert(tk.END, "Please enter a URL\n")
        return
    directories = read_directory_list(file_path)
    if directories:
        scan_directories(url, directories)

def highlight_search_text(output_field, search_text):
    if not search_text:
        messagebox.showinfo("Search Result", "Search cannot be blank", parent=directory_scan_frame)
        return

    output_field.tag_remove('highlight', '1.0', tk.END)
    output_field.tag_config('highlight', background='yellow', foreground='black')
    output_field.config(state=tk.NORMAL)

    start_index = "1.0"
    found = False
    while True:
        start_index = output_field.search(search_text, start_index, stopindex=tk.END)
        if not start_index:
            break
        found = True
        end_index = f"{start_index}+{len(search_text)}c"
        output_field.tag_add('highlight', start_index, end_index)
        start_index = end_index

    output_field.config(state=tk.DISABLED)
    if not found:
        messagebox.showinfo("Search Result", "No results found", parent=directory_scan_frame)

def run_admin_program():
    try:
        admin_path = os.path.join(os.path.dirname(__file__), "admin.py")
        subprocess.Popen(['python3', admin_path])
    except FileNotFoundError:
        output_field.insert(tk.END, "Admin program not found.\n")
    except Exception as e:
        output_field.insert(tk.END, f"Error running admin program: {str(e)}\n")

def directory_scan():
    first_frame.grid_forget()
    directory_scan_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")

def gather_info():
    first_frame.grid_forget()
    info_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")

def back_to_main():
    directory_scan_frame.grid_forget()
    info_frame.grid_forget()
    first_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")

# Modern UI Setup
root = tk.Tk()
root.title("Web Enumeration 🔍")
root.geometry("1100x800")
root.configure(bg="#1a1a1a")  # Dark background

# Style configuration
style = ttk.Style()
style.theme_use('clam')

# Custom styles
style.configure("TLabel", background="#1a1a1a", foreground="#00ffcc", font=("Helvetica", 14, "bold"))
style.configure("Title.TLabel", background="#1a1a1a", foreground="#ff4444", font=("Impact", 40))
style.configure("Round.TEntry", 
                fieldbackground="#2d2d2d", 
                background="#2d2d2d", 
                foreground="#00ffcc",
                borderwidth=0,
                padding=5,
                font=("Helvetica", 12))
style.map("Round.TEntry", 
          fieldbackground=[("active", "#333333")],
          background=[("active", "#333333")])

# First Frame (Main Menu)
first_frame = tk.Frame(root, bg="#1a1a1a", highlightthickness=2, highlightbackground="#ff4444")
first_frame.grid(row=0, column=0, rowspan=12, columnspan=12, sticky="nsew")
for i in range(12):
    first_frame.rowconfigure(i, weight=1)
    first_frame.columnconfigure(i, weight=1)

project_text = ttk.Label(first_frame, text="Web Enum X", style="Title.TLabel")
project_text.grid(row=1, column=3, columnspan=6, pady=50)

button_style = {
    "font": ("Helvetica", 14, "bold"),
    "bg": "#ff4444",
    "fg": "white",
    "activebackground": "#ff6666",
    "activeforeground": "white",
    "relief": "flat",
    "bd": 0,
    "width": 15,
    "height": 2
}

login_button = tk.Button(first_frame, text="Admin Login", command=run_admin_program, **button_style)
login_button.grid(row=5, column=5, pady=20)

directory_scan_button = tk.Button(first_frame, text="Directory Scan", command=directory_scan, **button_style)
directory_scan_button.grid(row=6, column=5, pady=20)

gather_info_button = tk.Button(first_frame, text="Gather Info", command=gather_info, **button_style)
gather_info_button.grid(row=7, column=5, pady=20)

exit_button = tk.Button(first_frame, text="Exit", command=root.quit, bg="#333333", fg="#ff4444", 
                       activebackground="#444444", activeforeground="#ff6666", font=("Helvetica", 14, "bold"),
                       relief="flat", bd=0, width=15, height=2)
exit_button.grid(row=8, column=5, pady=20)

# Directory Scan Frame
directory_scan_frame = tk.Frame(root, bg="#1a1a1a", highlightthickness=2, highlightbackground="#ff4444")
for i in range(12):
    directory_scan_frame.rowconfigure(i, weight=1)
    directory_scan_frame.columnconfigure(i, weight=1)

title_label = ttk.Label(directory_scan_frame, text="Directory Scanner", style="Title.TLabel")
title_label.grid(row=0, column=3, columnspan=6, pady=20)

ip_address_label = ttk.Label(directory_scan_frame, text="Target URL:")
ip_address_entry = ttk.Entry(directory_scan_frame, width=40, style="Round.TEntry")
ip_address_label.grid(row=1, column=2, padx=10, pady=10, sticky="e")
ip_address_entry.grid(row=1, column=3, columnspan=4, padx=10, pady=10)

browse_button = tk.Button(directory_scan_frame, text="Browse", command=browse_file, bg="#00cc99", fg="white",
                         activebackground="#00e6b8", activeforeground="white", font=("Helvetica", 12, "bold"),
                         relief="flat", bd=0, width=10)
browse_button.grid(row=2, column=3, pady=10)

start_button = tk.Button(directory_scan_frame, text="Scan", command=lambda: check_directories(file_path), **button_style)
start_button.grid(row=2, column=5, pady=10)

output_field = tk.Text(directory_scan_frame, height=20, width=80, bg="#2d2d2d", fg="#00ffcc", 
                      font=("Courier", 12), bd=0, highlightthickness=2, highlightbackground="#ff4444")
scrollbar = tk.Scrollbar(directory_scan_frame, command=output_field.yview, bg="#333333", troughcolor="#1a1a1a")
output_field.grid(row=3, column=2, rowspan=6, columnspan=6, padx=20, pady=20, sticky="nsew")
scrollbar.grid(row=3, column=8, rowspan=6, pady=20, sticky="ns")
output_field.configure(yscrollcommand=scrollbar.set)

search_container = tk.Frame(output_field, bg="#2d2d2d")
search_container.pack(side="top", fill="x")
search_entry = ttk.Entry(search_container, width=20, style="Round.TEntry")
search_entry.pack(side="left", padx=10, pady=5)
search_button = tk.Button(search_container, text="Search", command=lambda: highlight_search_text(output_field, search_entry.get()),
                         bg="#00cc99", fg="white", activebackground="#00e6b8", font=("Helvetica", 10, "bold"),
                         relief="flat", bd=0, width=8)
search_button.pack(side="left", padx=5, pady=5)
output_field.window_create("end", window=search_container)

save_button = tk.Button(directory_scan_frame, text="Save", command=save_output, bg="#00cc99", fg="white",
                       activebackground="#00e6b8", activeforeground="white", font=("Helvetica", 12, "bold"),
                       relief="flat", bd=0, width=10)
save_button.grid(row=9, column=4, pady=10)

back_button = tk.Button(directory_scan_frame, text="Back", command=back_to_main, bg="#333333", fg="#ff4444",
                       activebackground="#444444", activeforeground="#ff6666", font=("Helvetica", 12, "bold"),
                       relief="flat", bd=0, width=10)
back_button.grid(row=9, column=5, pady=10)

# Info Frame
info_frame = tk.Frame(root, bg="#1a1a1a", highlightthickness=2, highlightbackground="#ff4444")
for i in range(12):
    info_frame.rowconfigure(i, weight=1)
    info_frame.columnconfigure(i, weight=1)

info_title = ttk.Label(info_frame, text="Info Gatherer", style="Title.TLabel")
info_title.grid(row=0, column=3, columnspan=6, pady=20)

url_label = ttk.Label(info_frame, text="Target URL:")
url_entry = ttk.Entry(info_frame, width=40, style="Round.TEntry")
url_label.grid(row=1, column=2, padx=10, pady=10, sticky="e")
url_entry.grid(row=1, column=3, columnspan=4, padx=10, pady=10)

start_info_button = tk.Button(info_frame, text="Gather", command=start_gather_info, **button_style)
start_info_button.grid(row=2, column=5, pady=10)

output_field_info = tk.Text(info_frame, height=20, width=80, bg="#2d2d2d", fg="#00ffcc", 
                           font=("Courier", 12), bd=0, highlightthickness=2, highlightbackground="#ff4444")
scrollbar_info = tk.Scrollbar(info_frame, command=output_field_info.yview, bg="#333333", troughcolor="#1a1a1a")
output_field_info.grid(row=3, column=2, rowspan=6, columnspan=6, padx=20, pady=20, sticky="nsew")
scrollbar_info.grid(row=3, column=8, rowspan=6, pady=20, sticky="ns")
output_field_info.configure(yscrollcommand=scrollbar_info.set)

save_info_button = tk.Button(info_frame, text="Save", command=save_output, bg="#00cc99", fg="white",
                            activebackground="#00e6b8", activeforeground="white", font=("Helvetica", 12, "bold"),
                            relief="flat", bd=0, width=10)
save_info_button.grid(row=9, column=4, pady=10)

back_info_button = tk.Button(info_frame, text="Back", command=back_to_main, bg="#333333", fg="#ff4444",
                            activebackground="#444444", activeforeground="#ff6666", font=("Helvetica", 12, "bold"),
                            relief="flat", bd=0, width=10)
back_info_button.grid(row=9, column=5, pady=10)

root.mainloop()
