import logging
import os
import os.path as path
from os.path import join, getsize
import settings


class FilesController:

    @staticmethod
    def get_file_extension(file):
        list_file = file.split('.')
        return list_file[len(list_file)-1]

    @staticmethod
    def get_list_targets_from_the_road(path_):
        if path.exists(path_):
            list_ = os.walk(path_)
            target_files = []
            for root, dirs, files in list_:
                files_ = []
                for file in files:
                    files_.append(f"{root + ('/' if root[len(root)-1] != '/' else '') + file}")
                target_files += files_
                logging.info(f"{root} have {len(dirs)} dirs and  {len(files)} files")

            if settings.FILTER_FILE_EXTENSIONS_ACTIVE:
                logging.info(f"filter file extensions is active => {settings.FILTER_FILE_EXTENSIONS}")
                list_temp = []
                for path_f in target_files:
                    if FilesController.get_file_extension(path_f) in settings.FILTER_FILE_EXTENSIONS:
                        list_temp.append(path_f)
                target_files = list_temp
            logging.info(f"result => {target_files}")
            return target_files
        logging.warning(f"this road does not exist => {path_}")
        return []
