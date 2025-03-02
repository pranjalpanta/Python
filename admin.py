import tkinter as tk
from tkinter import ttk
import os

BASE_DIR = "/home/kali/Desktop/WebEnumerationfile"

def create_field_box(window, row, column, names, title): 
    frame = tk.Frame(window, bg="#2d2d2d", bd=0, highlightthickness=2, highlightbackground="#ff4444")
    frame.grid(row=row, column=column, padx=20, pady=20, sticky="nsew")
    frame.pack_propagate(False)

    title_label = ttk.Label(frame, text=title, style="SubTitle.TLabel")
    title_label.pack(pady=(10, 5))

    listbox = tk.Listbox(frame, font=('Courier', 12), bg="#1a1a1a", fg="#00ffcc",
                        selectbackground="#ff4444", selectforeground="white",
                        bd=0, highlightthickness=0)
    listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    scrollbar = tk.Scrollbar(listbox, command=listbox.yview, bg="#333333", troughcolor="#1a1a1a")
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.config(yscrollcommand=scrollbar.set)

    for name in names:
        listbox.insert(tk.END, name)

def list_files_with_extension(directory, extension):
    try:
        files = [file for file in os.listdir(directory) if file.endswith(extension)]
        return files
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error listing files: {str(e)}")
        return []

def admin_panel():
    root.destroy()

    window = tk.Tk()
    window.title("Admin Panel")
    window.geometry("900x700")
    window.config(bg="#1a1a1a")

    # Style configuration
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", background="#1a1a1a", foreground="#00ffcc", font=("Helvetica", 14, "bold"))
    style.configure("Title.TLabel", background="#1a1a1a", foreground="#ff4444", font=("Impact", 40))
    style.configure("SubTitle.TLabel", background="#2d2d2d", foreground="#00cc99", font=("Helvetica", 16, "bold"))
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

    # Layout configuration
    for i in range(5):
        window.rowconfigure(i, weight=1)
        window.columnconfigure(i, weight=1)

    title_label = ttk.Label(window, text="Admin Control", style="Title.TLabel")
    title_label.grid(row=0, column=1, columnspan=3, pady=30)

    scan_files = list_files_with_extension(BASE_DIR, ".txt")
    create_field_box(window, row=1, column=1, names=scan_files, title="Directory Scans")

    info_files = list_files_with_extension(BASE_DIR, ".txt")
    create_field_box(window, row=1, column=3, names=info_files, title="Web Info")

    exit_button = tk.Button(window, text="Exit", command=window.quit, 
                           bg="#333333", fg="#ff4444", 
                           activebackground="#444444", activeforeground="#ff6666", 
                           font=("Helvetica", 14, "bold"), relief="flat", bd=0, 
                           width=12, height=2)
    exit_button.grid(row=3, column=2, pady=20)

    window.mainloop()

def login():
    username = username_entry.get()
    password = password_entry.get()

    if username == "admin" and password == "admin":
        admin_panel()
    else:
        show_login_error()

def show_login_error():
    login_error_label.grid(row=4, column=0, columnspan=2, pady=10)

root = tk.Tk()
root.title("Admin Login")
root.geometry("800x600")
root.configure(bg="#1a1a1a")

style = ttk.Style()
style.theme_use('clam')
style.configure("TLabel", background="#1a1a1a", foreground="#00ffcc", font=("Helvetica", 12, "bold"))
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

login_frame = tk.Frame(root, bg="#1a1a1a", highlightthickness=2, highlightbackground="#ff4444")
login_frame.place(relx=0.5, rely=0.5, anchor="center", width=400, height=450)

login_label = ttk.Label(login_frame, text="Admin Login 🔒", style="Title.TLabel")
login_label.pack(pady=30)

username_label = ttk.Label(login_frame, text="Username:")
username_label.pack(pady=(20, 5))
username_entry = ttk.Entry(login_frame, width=30, style="Round.TEntry")
username_entry.pack()

password_label = ttk.Label(login_frame, text="Password:")
password_label.pack(pady=(20, 5))
password_entry = ttk.Entry(login_frame, width=30, show="*", style="Round.TEntry")
password_entry.pack()

login_button = tk.Button(login_frame, text="Login", command=login, 
                        bg="#ff4444", fg="white", 
                        activebackground="#ff6666", activeforeground="white", 
                        font=("Helvetica", 14, "bold"), relief="flat", bd=0, 
                        width=12, height=2)
login_button.pack(pady=30)

login_error_label = ttk.Label(login_frame, text="Invalid username or password", 
                             foreground="#ff4444", font=("Helvetica", 12))

root.mainloop()
