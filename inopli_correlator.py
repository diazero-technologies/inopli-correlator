import os
import time
import threading

from config.debug import DEBUG_MODE
from middleware.manager import MiddlewareManager





def main():
    # Initialize middleware manager
    middleware_manager = MiddlewareManager()
    
    # Load middleware configuration (includes tenants)
    if not middleware_manager.load_config():
        print("[ERROR] Failed to load middleware configuration. Exiting.")
        return
    
    if not middleware_manager.tenants_config:
        print("[ERROR] No tenants configured in middleware config. Exiting.")
        return

    # Create connectors
    if not middleware_manager.create_connectors():
        print("[ERROR] Failed to create middleware connectors. Exiting.")
        return
    
    if not middleware_manager.connectors:
        print("[ERROR] No enabled connectors found. Exiting.")
        return

    if DEBUG_MODE:
        print("[DEBUG] Middleware connectors created:")
        for name, connector in middleware_manager.connectors.items():
            print(f"  {name}: {connector.__class__.__name__}")

    print(f"[INFO] Created {len(middleware_manager.connectors)} middleware connectors")

    # Start middleware manager and connectors
    print("[INFO] Starting middleware manager...")
    middleware_manager.start()
    middleware_manager.start_connectors()

    # Keep the process alive
    print("[INFO] Inopli correlator with middleware running indefinitely. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[INFO] Shutdown requested. Stopping middleware...")
        middleware_manager.stop()
        print("[INFO] Exiting.")


if __name__ == "__main__":
    main()
