import logging
import os

LOG_FILE = os.path.join("logs", "waf.log")

if not os.path.isdir("logs"):
    os.makedirs("logs", exist_ok=True)

waf_logger = logging.getLogger("juice_shop_waf")
if not waf_logger.handlers:
    waf_logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    waf_logger.addHandler(file_handler)
    waf_logger.addHandler(console_handler)

