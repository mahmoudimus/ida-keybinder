# ida-keybinder
Emacs-like keybinding sequences for IDA Pro.

This plugin will exploit (abuse?) IDA Pro's Qt 5.15 implementation to enable Emacs-like Mnemonic Keybindings

## Installation

### Via HCLI (Recommended for IDA Pro 9.0+)

The easiest way to install ida-keybinder is through IDA's built-in plugin manager:

```bash
# From IDA Pro's HCLI
ida-hcli plugin install ida-keybinder
```

Or download from GitHub releases and install manually:
```bash
ida-hcli plugin install path/to/ida-keybinder-X.X.X.zip
```

### Via pip

```bash
# Install from PyPI
pip install ida-keybinder

# Or install from source
pip install -e .
```

### Manual Installation

Download the latest release and extract `keybinder.py` to your IDA plugins directory:
- Linux/macOS: `~/.idapro/plugins/`
- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
