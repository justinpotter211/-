# -*- mode: python ; coding: utf-8 -*-


from PyInstaller.utils.hooks import collect_data_files, collect_submodules

selenium_hiddenimports = collect_submodules("selenium")
selenium_datas = collect_data_files(
    "selenium",
    includes=["webdriver/common/windows/selenium-manager.exe"],
)
pystray_hiddenimports = collect_submodules("pystray")

a = Analysis(
    ['csu_autonet.py'],
    pathex=[],
    binaries=[],
    datas=selenium_datas,
    hiddenimports=selenium_hiddenimports + pystray_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CSUAutoNet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
