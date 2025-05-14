# datasources/linux.py

import os
import time
import importlib
from utils.event_logger import log_event
from config.debug import DEBUG_MODE

class LinuxMonitor:
    """
    Main class for Linux log monitoring. Supports both line-based and filesystem watcher rules.
    """

    def __init__(self, source_name, file_path, allowed_event_types):
        self.source_name = source_name
        self.file_path = file_path
        self.allowed_event_types = allowed_event_types
        self.rules = []
        self.offset = 0
        self.observer_initialized = False

        if DEBUG_MODE:
            print(f"[DEBUG] Initializing LinuxMonitor for {source_name} at {file_path}")
        self._load_rules()

    def _load_rules(self):
        """
        Loads rule classes from datasources/linux_rules using explicit mapping.
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
                instance = rule_class(self.source_name, self.allowed_event_types)
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
        Continuously reads the file line-by-line and passes it to all loaded rules,
        or starts filesystem observers for rules that require it.
        """
        try:
            if DEBUG_MODE:
                print(f"[DEBUG] Running monitor for {self.source_name}")

            # Start file watchers once
            if not self.observer_initialized:
                for rule in self.rules:
                    if hasattr(rule, "is_filesystem_watcher") and rule.is_filesystem_watcher:
                        if DEBUG_MODE:
                            print(f"[DEBUG] Starting filesystem watcher: {rule.__class__.__name__}")
                        rule.start_observer()
                self.observer_initialized = True

            # Continue with line-based monitoring if file exists
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"File not found: {self.file_path}")

            with open(self.file_path, "r") as file:
                file.seek(0, os.SEEK_END)  # Vai para o final do arquivo

                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.5)
                        continue

                    if DEBUG_MODE:
                        print(f"[DEBUG] Read line: {line.strip()}")

                    for rule in self.rules:
                        if hasattr(rule, "analyze_line"):
                            try:
                                if DEBUG_MODE:
                                    print(f"[DEBUG] Passing line to rule: {rule.__class__.__name__}")
                                rule.analyze_line(line)
                            except Exception as rule_err:
                                log_event(
                                    event_id=999,
                                    solution_name="inopli_monitor",
                                    data_source=self.source_name,
                                    class_name=rule.__class__.__name__,
                                    method="analyze_line",
                                    event_type="error",
                                    description=f"Exception in rule: {str(rule_err)}"
                                )
                                if DEBUG_MODE:
                                    print(f"[ERROR] Rule {rule.__class__.__name__} raised exception: {rule_err}")

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
