import wmi
import os
import pickle
from ast import literal_eval
from .fs_crypto import FS_Crypto


wmi_instance = wmi.WMI()

class Metadata:
    """Metadata class for managing filesystem metadata on a USB drive."""

    metadata_file = "metadata"
    metadata_path = None
    metadata = {
        "creation_date": None,
        "last_modified": None,
        "version": "1.0",
        "salt": None,
        "identifier": None,
        "max_files": 100,
        "file_count": 0,
        "deleted_count": 0,
        "file_table": None
    }

    @staticmethod
    def _wmi2dict(wmi_object):
        return dict((attr, getattr(wmi_object, attr)) for attr in wmi_object.__dict__['_properties'])
    
    @staticmethod
    def check_usb():
        # check if the drive is a USB drive with VolumeName "RKEY"
        for disk in wmi_instance.Win32_LogicalDisk():
            if disk.DriveType == 2 and disk.VolumeName == "RKEY":
                return disk.Name
        return None

    @classmethod
    def check_metadata(self, drive_letter):
        # construct full path to metadata file
        self.metadata_path = f"{drive_letter}\\{self.metadata_file}"
        if os.path.exists(self.metadata_path):
            return self.metadata_path
        else:
            return None
        
    @classmethod
    def write_metadata(self, password: str):
        if not self.metadata_path:
            raise ValueError("Metadata path is not set.")
        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError("Metadata file does not exist.")
        
        # encrypt before writing
        key, nonce = FS_Crypto.derive_key(
            password,
            FS_Crypto.get_hash(password.encode()).encode()
        )
        encrypted_metadata = FS_Crypto.encrypt(pickle.dumps(self.metadata), key, nonce)

        with open(self.metadata_path, 'wb') as f:
            f.write(encrypted_metadata)

    @classmethod
    def read_metadata(self, password: str):
        if not self.metadata_path:
            raise ValueError("Metadata path is not set.")
        if not os.path.exists(self.metadata_path):
            raise FileNotFoundError("Metadata file does not exist.")
        
        with open(self.metadata_path, 'rb') as f:
            encrypted_metadata = f.read()
        
        # decrypt before reading
        key, nonce = FS_Crypto.derive_key(
            password,
            FS_Crypto.get_hash(password.encode()).encode()
        )

        decrypted_metadata = FS_Crypto.decrypt(encrypted_metadata, key, nonce)
        if decrypted_metadata is None:
            raise ValueError("Decryption failed. Check your password.")
        self.metadata = pickle.loads(decrypted_metadata)

        return self.metadata
    
    @classmethod
    def update_metadata(self, field, value):
        if field not in self.metadata:
            raise KeyError(f"Field '{field}' does not exist in metadata.")
        
        self.metadata[field] = value