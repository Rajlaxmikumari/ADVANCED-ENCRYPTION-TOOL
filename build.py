# build.py
import PyInstaller.__main__

PyInstaller.__main__.run([
    'src/gui_app.py',
    '--onefile',
    '--windowed',
    '--name=AES_Encryption_Tool',
    '--icon=assets/icon.ico'  # Optional
])
