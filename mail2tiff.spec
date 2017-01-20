# -*- mode: python -*-

block_cipher = None


a = Analysis(['mail2tiff.py'],
             pathex=['C:\\Users\\GTC\\Desktop\\VIM\\python code'],
             binaries=None,
             datas=[('wkhtmltopdf.exe' , '.'), ('convert.exe', '.'), ('colors.xml', '.'), ('delegates.xml', '.'), ('magic.xml', '.')],
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
          name='mail2tiff',
          debug=False,
          strip=False,
          upx=True,
          console=True )
