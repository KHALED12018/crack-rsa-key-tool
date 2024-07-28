import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from sympy import factorint
from gmpy2 import mpz, invert, is_prime
import rsa
import threading

class RSAKeyExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Key Crack-By Dragon-noir-Dz")
        self.root.geometry("600x600")
        self.root.resizable(False, False)
        
        self.input_frame = tk.Frame(root, bg="#f5f5f5", padx=10, pady=10)
        self.input_frame.pack(padx=10, pady=10, fill=tk.X)
        
        tk.Label(self.input_frame, text="Enter N (Hex):", bg="#f5f5f5").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_n = tk.Entry(self.input_frame, width=50)
        self.entry_n.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(self.input_frame, text="Select e:", bg="#f5f5f5").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
       
        self.e_values = [3, 5, 7, 11, 17, 19, 65537]
        self.e_var = tk.StringVar(value=hex(self.e_values[0]))
        self.e_menu = ttk.Combobox(self.input_frame, textvariable=self.e_var, values=[hex(e) for e in self.e_values], state="readonly", width=47)
        self.e_menu.grid(row=1, column=1, padx=5, pady=5)
        
        self.result_frame = tk.Frame(root, bg="#eaeaea", padx=10, pady=10)
        self.result_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.result_text = scrolledtext.ScrolledText(self.result_frame, wrap=tk.WORD, height=20, bg="#ffffff", font=("Arial", 10))
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        self.progress = ttk.Progressbar(root, mode='indeterminate')
        self.progress.pack(padx=10, pady=10, fill=tk.X)
        
        self.extract_button = tk.Button(root, text="Extract Keys", command=self.start_extraction, bg="#4CAF50", fg="white", font=("Arial", 12))
        self.extract_button.pack(pady=10)
        
        self.root.configure(bg="#f5f5f5")

    def start_extraction(self):
        self.extract_button.config(state=tk.DISABLED)
        self.progress.start()
        threading.Thread(target=self.extract_keys).start()

    def extract_keys(self):
        try:
            n = mpz(int(self.entry_n.get(), 16))
            e = int(self.e_var.get(), 16)
            
            factors = factorint(n)
            if len(factors) == 2:
                p, q = factors.keys()
                if not (is_prime(p) and is_prime(q)):
                    raise ValueError("Factors are not prime numbers.")
                
                N = p * q
                phi_N = (p - 1) * (q - 1)
                d = invert(e, phi_N)

                public_key = rsa.PublicKey(N, e)
                private_key = rsa.PrivateKey(N, e, d, p, q)

                with open("private_key.pem", "wb") as priv_file:
                    priv_file.write(private_key.save_pkcs1('PEM'))
                with open("public_key.pem", "wb") as pub_file:
                    pub_file.write(public_key.save_pkcs1('PEM'))

                result_text = (
                    f"N (decimal) = {n}\n"
                    f"N (hex) = {hex(n)}\n"
                    f"e (decimal) = {e}\n"
                    f"e (hex) = {hex(e)}\n\n"
                    f"P (decimal) = {p}\n"
                    f"P (hex) = {hex(p)}\n"
                    f"Q (decimal) = {q}\n"
                    f"Q (hex) = {hex(q)}\n\n"
                    f"N = p * q = {p} * {q} = {N}\n"
                    f"φ(N) (decimal) = {phi_N}\n"
                    f"φ(N) (hex) = {hex(phi_N)}\n"
                    f"d (decimal) = {d}\n"
                    f"d (hex) = {hex(d)}\n\n"
                    f"Keys saved to:\n"
                    f"Private Key: private_key.pem\n"
                    f"Public Key: public_key.pem"
                )
                
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, result_text)
                
                messagebox.showinfo("Success", "Keys extracted and saved successfully!")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "Could not find two prime factors p and q.")
                messagebox.showerror("Error", "Could not find two prime factors p and q.")
        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            self.progress.stop()
            self.extract_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAKeyExtractorApp(root)
    root.mainloop()

