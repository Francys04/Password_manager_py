import sqlite3, hashlib 
from tkinter import *


# db code
# initilize the db
with sqlite3.connect("password_menu.db") as db:
    cursor = db.cursor()

cursor.execute("""
               CREATE TABLE IF NOT EXISTS masterpassword(
                   id INTIGER PRIMARY KEY,
                   password TEXT NOT NULL
               );
               """)

# initialize the window control
window = Tk()

window.title("Password_menu")

def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.hexdigest()
    
    return hash

def firstScreen():
    window.geometry("250x150")
    
    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()
        
    lbl1= Label(window, text='Re-enter Password')
    lbl1.pack()
    
    txt1 = Entry(window, width=20)
    txt1.pack()
    txt1.focus()
    
    lbl2 = Label(window)
    lbl2.pack()

    
    def savePassword():
        if txt.get() == txt1.get():
            
            hashedPasswords = hashPassword(txt.get().encode('utf-8'))
            
            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPasswords)])
            db.commit()
            
            passwordVault()
        else:
            lbl2.config(text='Password do not match')
    
    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=10)

def loginScreen():
    window.geometry("350x150")
    
    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()
        
    lbl1= Label(window)
    lbl1.pack()
    
    
    def getMasterPassord():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()
    
    def checkPassword():
        match = getMasterPassord()
        
        print(match)
        
        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="wrong password")
    
    btn = Button(window, text="Enter", command=checkPassword)
    # pady for space y-axis
    btn.pack(pady=10)
    
def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")
    
    lbl = Label(window, text="Password Vault")
    lbl.config(anchor=CENTER)
    lbl.pack()
        
    
cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstScreen()
    
window.mainloop()