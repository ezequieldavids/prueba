#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import sys
import requests
import threading
import configparser
import time
import traceback 

# --- IMPORTACIONES ---
from pkcs11 import Attribute, ObjectClass 
from cryptography.x509 import load_der_x509_certificate
from PyKCS11 import PyKCS11Lib, PyKCS11Error
# ---------------------

# Dependencias para la firma digital
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.pkcs11 import open_pkcs11_session, PKCS11Signer

# --- CONSTANTES DE LA APLICACIÓN ---
CONFIG_FILE = "configuracion.ini"
URL_DESCARGA = "/modulos/firma_digital/descargar_archivos.php"
URL_SUBIDA = "/modulos/firma_digital/subir_archivos_nw.php"


class FirmaController:
    """
    Encapsula toda la lógica de negocio del proceso de firma.
    """
    def __init__(self, config, datos_sia, archivos_a_firmar, pin_token, status_callback):
        self.config = config
        self.datos_sia = datos_sia
        self.archivos_a_firmar = archivos_a_firmar
        self.pin_token = pin_token
        self.report_status = status_callback
        self.dir_temp = Path(self.config['SIA']['dir_temp'])

    def ejecutar_proceso_completo(self):
        """
        Orquesta todo el flujo de trabajo: descargar, firmar, subir y limpiar.
        """
        try:
            self.report_status("Paso 1/4: Descargando archivos...", working=True)
            archivos_locales = self._descargar_archivos()

            self.report_status("Paso 2/4: Preparando para firmar...", working=True)
            self._firmar_documentos(archivos_locales)

            self.report_status("Paso 3/4: Subiendo archivos firmados...", working=True)
            self._subir_archivos()

            self.report_status("Paso 4/4: Limpiando archivos temporales...", working=True)
            self._limpiar_temp()

            return True, "¡Proceso completado con éxito!"

        except requests.exceptions.RequestException as e:
            return False, f"Error de red: {e}"
        except PyKCS11Error as e:
            return False, f"Error de Token/PKCS#11: Verifique el PIN y que el token esté conectado.\nDetalle: {e}"
        except Exception as e:
            tb_str = traceback.format_exc()
            return False, f"Ocurrió un error inesperado:\n\nTipo: {type(e).__name__}\nMensaje: {e}\n\nTraceback:\n{tb_str}"

    def _descargar_archivos(self):
        archivos_descargados = []
        url_base = self.config['SIA']['url_servidor'] + URL_DESCARGA
        
        for i, nombre_remoto in enumerate(self.archivos_a_firmar):
            self.report_status(f"Descargando {i+1}/{len(self.archivos_a_firmar)}: {nombre_remoto}")
            
            params = {'archivo': f"{self.datos_sia['carpeta']}__{nombre_remoto}"}
            response = requests.get(url_base, params=params, stream=True, timeout=30)
            response.raise_for_status()
            
            ruta_local = self.dir_temp / nombre_remoto
            with open(ruta_local, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            archivos_descargados.append(ruta_local)
        
        return archivos_descargados

    def _firmar_documentos(self, archivos_a_firmar_local):
        pkcs11_lib_path = self.config['PKCS11']['libreria']
        
        pkcs11_lib = PyKCS11Lib()
        pkcs11_lib.load(pkcs11_lib_path)
        slots = pkcs11_lib.getSlotList(tokenPresent=True)

        if not slots:
            raise RuntimeError("No se encontró ningún token/dispositivo de firma conectado.")

        with open_pkcs11_session(pkcs11_lib_path, user_pin=self.pin_token, slot_no=slots[0]) as session:
            
            signer = PKCS11Signer(pkcs11_session=session)

            if signer.signing_cert is None:
                raise RuntimeError(
                    "Error: El firmador (pyhanko) encontró una clave privada "
                    "pero no pudo encontrar su certificado correspondiente en el token."
                )

            template = {
                Attribute.CLASS: ObjectClass.CERTIFICATE
            }
            all_cert_handles = session.get_objects(template)
            
            all_certs_from_token = []
            for cert_handle in all_cert_handles:
                try:
                    cert_der = cert_handle[Attribute.VALUE]
                    cert_obj = load_der_x509_certificate(bytes(cert_der))
                    all_certs_from_token.append(cert_obj)
                        
                except Exception as e:
                    print(f"Aviso: No se pudo leer un certificado del token: {e}")

            signer.other_certs_to_embed = all_certs_from_token
            
            for i, ruta_pdf in enumerate(archivos_a_firmar_local):
                self.report_status(f"Firmando {i+1}/{len(archivos_a_firmar_local)}: {ruta_pdf.name}")
                
                nombre_salida = ruta_pdf.stem + "_signed.pdf"
                ruta_salida = self.dir_temp / nombre_salida

                with ruta_pdf.open('rb') as f_in, ruta_salida.open('wb') as f_out:
                    writer = IncrementalPdfFileWriter(f_in)
                    
                    unique_field_name = f"Signature-{int(time.time())}"
                    
                    signers.sign_pdf(
                        writer,
                        signers.PdfSignatureMetadata(field_name=unique_field_name),
                        signer=signer
                    )
                    writer.write(f_out)

    def _subir_archivos(self):
        url_subida = self.config['SIA']['url_servidor'] + URL_SUBIDA
        archivos_firmados = list(self.dir_temp.glob('*_signed.pdf'))
        
        for i, ruta_firmada in enumerate(archivos_firmados):
            self.report_status(f"Subiendo {i+1}/{len(archivos_firmados)}: {ruta_firmada.name}")
            
            nombre_original = ruta_firmada.name.replace('_signed.pdf', '.pdf')
            partes_nombre = nombre_original.split('__')
            
            params_query = {
                'params': f"{self.datos_sia['tabla1']}*{self.datos_sia['id_usuario']}*{self.datos_sia['tabla2']}*{self.datos_sia['id2']}*/*/{partes_nombre[1]}/{partes_nombre[2]}",
                'carpeta': self.datos_sia['carpeta'],
                'archivo_uno': partes_nombre[1].replace('/', '-'),
                'archivo_dos': partes_nombre[2].replace('/', '-')
            }
            
            with ruta_firmada.open('rb') as f:
                files = {'file': (ruta_firmada.name, f, 'application/pdf')}
                response = requests.post(url_subida, params=params_query, files=files, timeout=60)
                response.raise_for_status()

    def _limpiar_temp(self):
        for f in self.dir_temp.glob('*'):
            try:
                if f.is_file():
                    f.unlink()
            except OSError as e:
                print(f"Aviso: No se pudo borrar el archivo temporal {f}: {e}")


class AppFirmador(tk.Tk):
    """
    Clase principal de la aplicación. Gestiona la ventana y los widgets (UI).
    """
    def __init__(self):
        super().__init__()
        
        self.title("Firmador Moderno SIA v3.6")
        self.geometry("450x280")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        self.config = {}
        self.is_working = False
        
        # Inicializamos las variables para que existan
        self.archivos_a_firmar = []
        self.datos_sia = {}

        if not self._cargar_configuracion() or not self._procesar_argumentos():
            self.after(100, self.destroy)
            return
            
        # --- CORRECCIÓN ---
        # La llamada a _crear_widgets() faltaba
        self._crear_widgets()
        self.eval('tk::PlaceWindow . center') # Centrar al final

    def _crear_widgets(self):
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Ingrese el PIN de su Token:", font=("Helvetica", 12)).pack(pady=(0, 5))
        
        self.pin_entry = ttk.Entry(main_frame, show="*", width=35)
        self.pin_entry.pack(pady=5)
        self.pin_entry.focus_set()

        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.pack(pady=15, fill=tk.X, expand=True)
        
        # --- CORRECCIÓN ---
        # El padre debe ser 'main_frame' y usamos 'self.archivos_a_firmar'
        self.status_label = ttk.Label(main_frame, text=f"Listo para firmar {len(self.archivos_a_firmar)} documento(s).")
        self.status_label.pack(pady=5)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=15)
        
        self.firmar_button = ttk.Button(button_frame, text="Firmar Documentos", command=self.iniciar_proceso_firma)
        self.firmar_button.pack(side=tk.LEFT, padx=10)
        
        self.cerrar_button = ttk.Button(button_frame, text="Cerrar", command=self.destroy)
        self.cerrar_button.pack(side=tk.LEFT, padx=10)
        
        self.bind('<Return>', lambda event: self.iniciar_proceso_firma())


    def _cargar_configuracion(self):
        try:
            ruta_config = Path(CONFIG_FILE)
            if not ruta_config.exists():
                messagebox.showerror("Error de Configuración", f"No se encontró el archivo '{CONFIG_FILE}'.")
                return False
            
            parser = configparser.ConfigParser()
            parser.read(ruta_config)

            self.config = {
                'SIA': dict(parser['SIA']),
                'PKCS11': dict(parser['PKCS11'])
            }
            
            Path(self.config['SIA']['dir_temp']).mkdir(exist_ok=True)
            return True

        except (configparser.Error, KeyError) as e:
            messagebox.showerror("Error de Configuración", f"El archivo '{CONFIG_FILE}' está mal formado o le faltan datos.\nDetalle: {e}")
            return False

    def _procesar_argumentos(self):
        try:
            if len(sys.argv) < 2:
                messagebox.showerror("Argumento Faltante", "Falta el archivo de definición de firma como argumento.")
                return False

            with Path(sys.argv[1]).open('r') as f:
                linea = f.readline().strip()
                
            partes = linea.split(':')
            if len(partes) < 7:
                raise ValueError("El archivo de definición no contiene todas las partes necesarias.")

            self.datos_sia = {'tabla1': partes[0], 'id1': partes[1], 'tabla2': partes[2], 'id2': partes[3], 'carpeta': partes[4], 'id_usuario': partes[5]}
            self.archivos_a_firmar = [a for a in partes[6].split('*') if a]
            
            if not self.archivos_a_firmar:
                raise ValueError("No se especificaron archivos para firmar.")
                
            return True
        except Exception as e:
            messagebox.showerror("Error de Argumento", f"No se pudo procesar el archivo de entrada:\n{e}")
            return False

    def actualizar_estado(self, text, working=False):
        def _update():
            self.status_label.config(text=text)
            self.is_working = working
            
            if working:
                self.progress_bar.start(10)
                for widget in (self.firmar_button, self.cerrar_button, self.pin_entry):
                    widget.config(state=tk.DISABLED)
            else:
                self.progress_bar.stop()
                for widget in (self.firmar_button, self.cerrar_button, self.pin_entry):
                    widget.config(state=tk.NORMAL)
        
        self.after(0, _update)

    def iniciar_proceso_firma(self):
        pin_token = self.pin_entry.get()
        if not pin_token:
            messagebox.showwarning("PIN Requerido", "Por favor, ingrese el PIN de su token.")
            return
        
        self.pin_entry.delete(0, tk.END)

        controller = FirmaController(self.config, self.datos_sia, self.archivos_a_firmar, pin_token, self.actualizar_estado)
        threading.Thread(target=self.proceso_en_hilo, args=(controller,), daemon=True).start()

    def proceso_en_hilo(self, controller: FirmaController):
        success, message = controller.ejecutar_proceso_completo()
        
        controller.pin_token = None

        if success:
            self.actualizar_estado(message, working=False)
            messagebox.showinfo("Éxito", message)
            self.after(0, self._configurar_para_cierre)
        else:
            self.actualizar_estado("Proceso fallido. Listo para reintentar.", working=False)
            messagebox.showerror("Error en el Proceso", message)

    def _configurar_para_cierre(self):
        self.firmar_button.config(text="Finalizado", state=tk.DISABLED)
        self.cerrar_button.config(text="Cerrar")
        self.cerrar_button.focus_set()

    def _on_closing(self):
        if self.is_working:
            if messagebox.askyesno("Confirmar", "¿El proceso de firma está en curso, ¿estás seguro de que quieres salir?"):
                self.destroy()
        else:
            self.destroy()


if __name__ == "__main__":
    print("Ejecutando Firmador Moderno SIA v3.6...")
    
    app = AppFirmador()
        
    app.mainloop()