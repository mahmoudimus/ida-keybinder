import dataclasses
import functools
import logging
import re
import sys
import typing

import idaapi

# Optional: ida-settings (new Hex-Rays settings infra)
try:
    import ida_settings
except ImportError:
    ida_settings = None


# ------------------------------------------------------------------------------
# Version helpers
# ------------------------------------------------------------------------------


@functools.total_ordering
@dataclasses.dataclass(frozen=True)
class IDAVersionInfo:
    major: int
    minor: int
    sdk_version: int

    def __eq__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) == (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) == tuple(other[:2])
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) < (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) < tuple(other[:2])
        return NotImplemented

    @staticmethod
    @functools.cache
    def ida_version():
        version_str: str = idaapi.get_kernel_version()  # e.g. "9.1"
        sdk_version: int = idaapi.IDA_SDK_VERSION
        major, minor = map(int, version_str.split("."))
        return IDAVersionInfo(major, minor, sdk_version)


ida_version = IDAVersionInfo.ida_version

SUPPORTED_PYTHON = sys.version_info[0] == 3

try:
    IDA_GLOBAL_SCOPE = sys.modules["__main__"]
    SUPPORTED_IDA = ida_version() >= (7, 6)
except Exception:
    SUPPORTED_IDA = False

SUPPORTED_ENVIRONMENT = bool(SUPPORTED_IDA and SUPPORTED_PYTHON)

# settings key to be declared in ida-plugin.json
SETTINGS_KEY_ENABLED = "enabled"


if typing.TYPE_CHECKING:
    from PySide6.QtGui import QAction as QActionType
else:
    QActionType = None

if ida_version() >= (9, 2):
    from PySide6 import QtWidgets, QtGui

    QAction = QtGui.QAction
    QApplication = QtWidgets.QApplication
    if not typing.TYPE_CHECKING:
        QAction = QtGui.QAction
else:
    from PyQt5 import QtWidgets

    QAction = QtWidgets.QAction
    QApplication = QtWidgets.QApplication

    if not typing.TYPE_CHECKING:
        QAction = QtWidgets.QAction
# ------------------------------------------------------------------------------
# Python logging → IDA output handler
# ------------------------------------------------------------------------------


class IDALogHandler(logging.Handler):
    """
    Logging handler that routes Python logging records to IDA's message window.
    """

    __HANDLER_NAME__ = "keybinder.ida_handler"

    def __init__(self):
        super().__init__()
        self.name = self.__HANDLER_NAME__

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            lvl = record.levelno

            # Newer IDA has msg_info/msg_warn/msg_err
            if lvl >= logging.ERROR:
                idaapi.msg(f"ERROR: {msg}\n")
            elif lvl >= logging.WARNING:
                idaapi.msg(f"WARNING: {msg}\n")
            else:
                idaapi.msg(f"INFO: {msg}\n")
        except Exception:
            # Avoid raising during logging
            try:
                idaapi.msg("Logging failure in IDALogHandler\n")
            except Exception:
                pass


def create_plugin_logger(name: str) -> logging.Logger:
    """
    Create/configure a logger for this plugin, without touching global logging
    config beyond the one logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid adding multiple handlers if plugin is reloaded
    for h in list(logger.handlers):
        if getattr(h, "name", None) == IDALogHandler.__HANDLER_NAME__:
            logger.removeHandler(h)

    handler = IDALogHandler()
    # Example formatting: [Keybinder] INFO: message
    handler.setFormatter(logging.Formatter(f"[{name}] %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    # Don't propagate to root logger by default
    # logger.handlers = [h for h in logger.handlers if isinstance(h, IDALogHandler)]
    logger.propagate = False

    return logger


# ------------------------------------------------------------------------------
# Settings wrapper
# ------------------------------------------------------------------------------


class SettingsAdapter:
    def __init__(
        self,
        settings_mod,
        key_enabled: str,
        default_enabled: bool,
        logger: logging.Logger,
    ):
        self._settings_mod = settings_mod
        self._key_enabled = key_enabled
        self._default_enabled = default_enabled
        self._logger = logger

    def _get_bool(self, key: str, default: bool) -> bool:
        if self._settings_mod is None:
            return default

        try:
            value = self._settings_mod.get_current_plugin_setting(key)
        except Exception:
            # Missing setting → default
            return default

        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("1", "true", "yes", "on")
        return default

    def plugin_enabled(self) -> bool:
        enabled = self._get_bool(self._key_enabled, self._default_enabled)
        self._logger.debug(f"plugin_enabled -> {enabled}")
        return enabled


# ------------------------------------------------------------------------------
# Keybinding manager (all state lives here)
# ------------------------------------------------------------------------------


class KeybindingManager:
    _TILDE_PATTERN_RGX = re.compile(r"~(.*?)~")

    def __init__(self, plugin_name: str, logger: logging.Logger):
        self._plugin_name = plugin_name
        self._logger = logger
        self._bindings = {
            "ChooserEdit": "Meta+E, C",
            "TilEditType": "Meta+E, T",
            "EditSegment": "Meta+E, S",
            "TilExpandStruct": "Meta+E, E",
            "SetSegmentRegister": "Meta+E, R",
            "Edit/Plugins/IDA Patcher": "Meta+P, P",
            "Edit/Plugins/Signature Maker (py)": "Meta+P, S",
            "ai_assistant:rename_all": "Meta+P, Ctrl+R",
            "ai_assistant:rename": "Meta+P, Ctrl+F",
            "ai_assistant:analyze": "Meta+P, Ctrl+A",
            "mutilz:force_analyze": "Meta+M, A",
            "mutilz:re_decompile_function": "Meta+M, D",
        }
        self._applied = False
        # action_name -> QAction
        self._actions: dict[str, QActionType] = {}

    @staticmethod
    def _replace_tilde_with_ampersand(text: str) -> str:
        # IDA labels use ~X~ to mark mnemonic; Qt uses &X
        return KeybindingManager._TILDE_PATTERN_RGX.sub(
            lambda m: f"&{m.group(1)}",
            text or "",
        )

    def _enumerate_qactions(self) -> dict[str, QActionType]:
        """
        Walk the Qt widget tree and collect all QActions keyed by their text().
        """
        if QApplication is None or QAction is None:
            self._logger.error("Qt not available; cannot enumerate QActions.")
            return {}

        main_window = QApplication.instance()
        if main_window is None:
            self._logger.error("No QApplication instance; cannot enumerate QActions.")
            return {}

        label_to_action: dict[str, QActionType] = {}

        widgets = [main_window]
        while widgets:
            widget = widgets.pop(0)

            # enqueue children
            try:
                widgets.extend(list(widget.findChildren(QAction)))
            except Exception:
                pass

            if not isinstance(widget, QAction):
                continue

            label_to_action[widget.text()] = widget

        self._logger.debug(f"Enumerated {len(label_to_action)} QActions.")
        return label_to_action

    def dump_all_ida_actions(self):
        actions = idaapi.get_registered_actions()
        self._logger.info("Total actions registered: %s", len(actions))

        for name in actions:
            label = idaapi.get_action_label(name) or ""
            shortcut = idaapi.get_action_shortcut(name) or ""
            tooltip = idaapi.get_action_tooltip(name) or ""
            self._logger.info(f"{name:25}  {shortcut:12}  {label}  [{tooltip}]")

    def _build_action_map(self):
        """
        Build mapping from IDA action_name -> QAction using labels:
        - get_action_label() from IDA
        - convert ~X~ to &X
        - lookup corresponding QAction by text
        """
        label_to_action = self._enumerate_qactions()
        if not label_to_action:
            return

        for action_name in idaapi.get_registered_actions():
            # keep original behavior: only consider actions that already
            # have an IDA shortcut
            # TODO: make this a setting
            # if not idaapi.get_action_shortcut(action_name):
            #     continue

            label = idaapi.get_action_label(action_name)
            # TODO: make this a setting
            if not label:
                continue

            qt_label = self._replace_tilde_with_ampersand(label)
            qact = label_to_action.get(qt_label)
            if not qact:
                self._logger.debug(
                    f"Action '{action_name}' (label '{qt_label}') "
                    f"not found in QAction list."
                )
                continue

            self._actions[action_name] = qact

        self._logger.info(
            f"Mapped {len(self._actions)} IDA actions to QActions " f"for keybinding."
        )

    def apply(self):
        """
        Apply Emacs-like chords by calling QAction.setShortcut(),
        so multi-stroke sequences like 'Meta+P, S' work without
        tripping IDA's collision logic.
        """
        if self._applied:
            self._logger.debug("apply() called but already applied; skipping.")
            return
        self._applied = True

        if QApplication is None or QAction is None:
            self._logger.error("Qt not available; cannot apply shortcuts.")
            return

        # Build the action_name -> QAction mapping once
        self._build_action_map()

        self._logger.info("Setting shortcuts via QActions.")

        for action_name, shortcut in self._bindings.items():
            qact = self._actions.get(action_name)
            if not qact:
                self._logger.warning(
                    f"action '{action_name}' not found; cannot set '{shortcut}'"
                )
                continue

            qact.setShortcut(shortcut)
            self._logger.info(f"{action_name} -> {shortcut}")

    def apply2(self):
        if self._applied:
            self._logger.debug("apply() called but already applied; skipping.")
            return
        self._applied = True

        self._logger.info("Setting shortcuts.")

        for action_name, shortcut in self._bindings.items():
            label = idaapi.get_action_label(action_name)
            if not label:
                self._logger.warning(
                    f"action '{action_name}' not found; cannot set '{shortcut}'"
                )
                continue

            ok = idaapi.update_action_shortcut(action_name, shortcut)
            if ok:
                self._logger.info(f"{action_name} -> {shortcut}")
            else:
                self._logger.error(f"failed to set '{shortcut}' for '{action_name}'")


# ------------------------------------------------------------------------------
# UI hook: run once when UI is ready
# ------------------------------------------------------------------------------


class KeyHooker(idaapi.UI_Hooks):
    def __init__(
        self,
        settings: SettingsAdapter,
        manager: KeybindingManager,
        logger: logging.Logger,
    ):
        super().__init__()
        self._settings = settings
        self._manager = manager
        self._logger = logger

    def ready_to_run(self):
        """
        Called once the UI is fully initialized.
        Perfect time to tweak action shortcuts.
        """
        if self._settings.plugin_enabled():
            self._logger.debug("UI ready; applying keybindings.")
            self._manager.apply()
        else:
            self._logger.info("Disabled via settings; not applying shortcuts.")

    def get_lines_rendering_info(self, out, widget, rin):
        return 0

    def populating_widget_popup(self, widget, popup, ctx):
        pass


# ------------------------------------------------------------------------------
# IDA Plugin
# ------------------------------------------------------------------------------


class KeybinderPlugin(idaapi.plugin_t):
    """
    The Keybinder plugin: set Emacs-like key chords for core actions.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_UNL
    comment = (
        "A plugin to enable Emacs-like key sequences and key chord sequences in IDA"
    )
    help = ""
    wanted_name = "Keybinder"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()

        self.logger = create_plugin_logger(self.wanted_name)

        self.__updated = getattr(
            sys.modules.get("__main__", object()), "RESTART_REQUIRED", False
        )

        self._settings = SettingsAdapter(
            settings_mod=ida_settings,
            key_enabled=SETTINGS_KEY_ENABLED,
            default_enabled=True,
            logger=self.logger,
        )
        self._manager = KeybindingManager(self.wanted_name, self.logger)
        self._ui_hook = None

    def init(self):
        if not SUPPORTED_ENVIRONMENT or self.__updated:
            self.logger.warning(
                "Unsupported environment or restart required; skipping."
            )
            return idaapi.PLUGIN_SKIP

        if not self._settings.plugin_enabled():
            self.logger.info("Loaded but disabled via settings; not hooking UI.")
            return idaapi.PLUGIN_KEEP

        self._ui_hook = KeyHooker(self._settings, self._manager, self.logger)
        self._ui_hook.hook()

        self.logger.debug("Plugin init complete; UI hook installed.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Called when this file is loaded as a script (Alt+F7, etc.).
        Let the user re-apply keybindings manually.
        """
        if not self._settings.plugin_enabled():
            self.logger.info("Disabled via settings; run() skipped.")
            return

        self.logger.debug("run() called; applying keybindings.")
        self._manager.apply()

    def term(self):
        if self._ui_hook is not None:
            self._ui_hook.unhook()
            self._ui_hook = None
        self.logger.debug("Plugin terminated.")


def PLUGIN_ENTRY():
    if not SUPPORTED_ENVIRONMENT:
        # we *could* create a logger here, but if we’re incompatible,
        # just use a plain message and bail early.
        print(
            "plugin",
            KeybinderPlugin.wanted_name,
            "is not compatible with this IDA/Python version",
        )
        return idaapi.PLUGIN_SKIP
    return KeybinderPlugin()
