# datasources/linux.py

import os
import time
import importlib
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.event_logger import log_event
from config.debug import DEBUG_MODE
from utils.tenant_router import resolve_tenant


class LinuxLogHandler(FileSystemEventHandler):
    """
    Watchdog handler for monitoring Linux log files.
    """

    def __init__(self, monitor):
        self.monitor = monitor
        self.file = None
        self.position = 0
        self._open_file()

    def _open_file(self):
        """Safely open the file and seek to the end"""
        try:
            if self.file:
                self.file.close()
            self.file = open(self.monitor.file_path, "r")
            self.file.seek(0, os.SEEK_END)
            self.position = self.file.tell()
        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.monitor.source_name,
                class_name="LinuxLogHandler",
                method="_open_file",
                event_type="error",
                description=str(e)
            )

    def on_modified(self, event):
        """Handle file modification events"""
        if event.src_path != self.monitor.file_path:
            return

        try:
            if not self.file or self.file.closed:
                self._open_file()
                return

            self.file.seek(self.position)

            while True:
                line = self.file.readline()
                if not line:
                    break

                if DEBUG_MODE:
                    print(f"[DEBUG] Read line: {line.strip()}")

                for rule in self.monitor.rules:
                    if hasattr(rule, "analyze_line"):
                        try:
                            if DEBUG_MODE:
                                print(f"[DEBUG] Passing line to rule: {rule.__class__.__name__}")
                            rule.analyze_line(line)
                        except Exception as rule_err:
                            log_event(
                                event_id=999,
                                solution_name="inopli_monitor",
                                data_source=self.monitor.source_name,
                                class_name=rule.__class__.__name__,
                                method="analyze_line",
                                event_type="error",
                                description=f"Exception in rule: {str(rule_err)}"
                            )
                            if DEBUG_MODE:
                                print(f"[ERROR] Rule {rule.__class__.__name__} raised exception: {rule_err}")

            self.position = self.file.tell()

        except Exception as e:
            self._open_file()  # Reopen file on any error
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.monitor.source_name,
                class_name="LinuxLogHandler",
                method="on_modified",
                event_type="error",
                description=str(e)
            )

    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.src_path == self.monitor.file_path:
            if self.file:
                self.file.close()
            self.file = None
            self.position = 0

    def on_created(self, event):
        """Handle file creation events"""
        if event.src_path == self.monitor.file_path:
            self._open_file()


class LinuxMonitor:
    """
    Main class for Linux log monitoring. Supports both line-based and filesystem watcher rules.
    Uses watchdog for reliable file monitoring and integrates with multi-tenant logic.
    """

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.rules = []
        self.observer = None
        self.observer_initialized = False

        # Host metadata for tenant filtering
        self.hostname = socket.gethostname()
        if DEBUG_MODE:
            print(f"[DEBUG] Initializing LinuxMonitor for {source_name} at {file_path} on host {self.hostname}")

        self._load_rules()

    def _load_rules(self):
        """
        Loads rule classes from datasources/linux_rules using explicit mapping.
        Also injects multi-tenant support into rule instances.
        """
        rule_modules = {
            "bruteforce_rule": "BruteforceRule",
            "user_enum_rule": "UserEnumerationRule",
            "sudo_denied_rule": "SudoDeniedRule",
            "sudo_group_mod_rule": "SudoGroupModificationRule",
            "root_shell_rule": "RootShellExecutionRule",
            "new_user_rule": "NewUserCreationRule",
            "crontab_mod_rule": "CrontabModificationRule",
            "systemd_persistence_rule": "SystemdPersistenceRule",
            "ssh_key_injection_rule": "SshKeyInjectionRule"
        }

        for module_name, class_name in rule_modules.items():
            try:
                if DEBUG_MODE:
                    print(f"[DEBUG] Loading rule module: {module_name}")
                module = importlib.import_module(f"datasources.linux_rules.{module_name}")
                rule_class = getattr(module, class_name)

                # Instantiate rule with source and allowed events
                instance = rule_class(
                    self.source_name,
                    self.allowed_event_types
                )

                # Inject host metadata and tenant resolver
                instance.hostname = self.hostname
                instance.resolve_tenant = resolve_tenant

                self.rules.append(instance)

                if DEBUG_MODE:
                    print(f"[DEBUG] Loaded rule class: {class_name}")

            except Exception as e:
                log_event(
                    event_id=996,
                    solution_name="inopli_monitor",
                    data_source=self.source_name,
                    class_name="LinuxMonitor",
                    method="_load_rules",
                    event_type="error",
                    description=f"Failed to load rule {module_name}: {str(e)}"
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Failed to load rule {module_name}: {str(e)}")

    def run(self):
        """
        Start monitoring the log file using watchdog observer and
        initialize filesystem watchers for rules that require it.
        """
        try:
            if DEBUG_MODE:
                print(f"[DEBUG] Running monitor for {self.source_name}")

            # Start filesystem watchers once
            if not self.observer_initialized:
                for rule in self.rules:
                    if hasattr(rule, "is_filesystem_watcher") and rule.is_filesystem_watcher:
                        if DEBUG_MODE:
                            print(f"[DEBUG] Starting filesystem watcher: {rule.__class__.__name__}")
                        rule.start_observer()
                self.observer_initialized = True

            # Set up file monitoring if directory exists
            if not os.path.exists(os.path.dirname(self.file_path)):
                raise FileNotFoundError(f"Directory not found: {os.path.dirname(self.file_path)}")

            event_handler = LinuxLogHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, os.path.dirname(self.file_path), recursive=False)
            self.observer.start()

            if DEBUG_MODE:
                print(f"[INFO] Started watchdog observer for {self.file_path}")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.observer.stop()

            self.observer.join()

        except Exception as e:
            log_event(
                event_id=995,
                solution_name="inopli_monitor",
                data_source=self.source_name,
                class_name=self.__class__.__name__,
                method="run",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Exception in LinuxMonitor.run(): {e}")
