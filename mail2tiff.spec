# -*- mode: python -*-

block_cipher = None


a = Analysis(['mail.py'],
             pathex=['C:\\Users\\GTC\\Desktop\\VIM\\python code'],
             binaries=None,
             datas=[('wkhtmltopdf.exe' , '.'), ('convert.exe', '.'), ('gswin32c.exe', '.'), ('gsdll64.dll', '.'), ('vcomp100.dll', '.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='mail',
          debug=False,
          strip=False,
          upx=True,
          console=True )
