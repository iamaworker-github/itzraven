# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Itzraven standalone binary."""

import os
import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['itzraven/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('itzraven/ui/**/*.tcss', 'itzraven/ui'),
        ('itzraven/skills/*.md', 'itzraven/skills'),
        ('itzraven/prompts/*.txt', 'itzraven/prompts'),
    ],
    hiddenimports=[
        'itzraven.core',
        'itzraven.core.blackboard',
        'itzraven.core.cvss_scorer',
        'itzraven.core.llm_deduplicator',
        'itzraven.core.pr_generator',
        'itzraven.core.thinking_chain',
        'itzraven.core.todo_manager',
        'itzraven.core.events',
        'itzraven.agents',
        'itzraven.agents.base_agent',
        'itzraven.agents.orchestrator',
        'itzraven.agents.modes',
        'itzraven.agents.llm_client',
        'itzraven.toolkit',
        'itzraven.ui',
        'itzraven.reporting',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'notebook',
        'ipykernel',
        'jupyter_client',
        'pandas',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='itzraven',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='itzraven/ui/assets/icon.ico' if Path('itzraven/ui/assets/icon.ico').exists() else None,
)

# Build script: pyinstaller itzraven.spec --clean --onefile
