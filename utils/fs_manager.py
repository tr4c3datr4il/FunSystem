import os
import uuid
import winreg
import platform
from datetime import datetime
from .fs_crypto import FS_Crypto
from .fs_metadata import Metadata
from .color import Color


color = Color()

class MyFSManager:
    """File System Manager class"""

    def __init__(self, disk_name="MyFS.DRI"):
        self.disk_name = disk_name
        self.file_table = []
        self.master_key = None
        self.nonce = None
        self.metadata = None
        self.is_initialized = False
        self.access_password = None
        self.header = b"MyFS\x00"
    
    def verify_password(self, input_access_password):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        
        # try decrypting the metadata and filesystem with the provided password
        try:
            temp_metadata = Metadata.read_metadata(input_access_password)
            temp_master_key, temp_nonce = FS_Crypto.derive_key(
                input_access_password,
                temp_metadata["salt"]
            )
            with open(self.disk_name, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = FS_Crypto.decrypt(encrypted_data, temp_master_key, nonce=temp_nonce)
            if decrypted_data is not None:
                return True
        except Exception as e:
            color._print(f"Password verification failed: {e}", color.WRONG)
            return False
    
    def change_password(self, old_password, new_password):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        
        # verify old password
        if not self.verify_password(old_password):
            raise ValueError("Old password is incorrect.")
        
        # decrypt with old credentials
        if self._is_encrypted():
            self._decrypt_filesystem()

        # set new master key and nonce
        salt = os.urandom(16)
        new_master_key, new_nonce = FS_Crypto.derive_key(new_password, salt)
        
        self.metadata["salt"] = salt
        Metadata.update_metadata("salt", salt)
        Metadata.write_metadata(new_password)
        
        self.master_key = new_master_key
        self.nonce = new_nonce
        self.access_password = new_password
        
        # re-encrypt filesystem with new credentials
        self._encrypt_filesystem()

    def initialize_filesystem(self, access_password):
        salt = os.urandom(16)
        self.master_key, self.nonce = FS_Crypto.derive_key(access_password, salt)
        # print(f"Master key: {self.master_key.hex()}")
        # print(f"Nonce: {self.nonce.hex()}")
        self.access_password = access_password
        creation_time = datetime.now()
        # each machine has a unique MachineGuid value in the registry so we can use it as an identifier
        machine_guid = winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"), "MachineGuid")[0]
        # hash it so people can't easily guess it
        identifier = FS_Crypto.get_hash(machine_guid.encode())
        # create header with identifier and Windows build version
        self.header += bytes.fromhex(identifier) + b'\x00' + platform.platform().encode() + b'\x00\x01\x02'

        # update metadata
        Metadata.update_metadata("creation_date", creation_time)
        Metadata.update_metadata("last_modified", creation_time)
        Metadata.update_metadata("salt", salt)
        Metadata.update_metadata("identifier", identifier)
        Metadata.write_metadata(self.access_password)
        self.metadata = Metadata.metadata

        # init disk
        self._create_filesystem_structure()
        self.is_initialized = True
        self.save_filesystem()
        
    def load_filesystem(self, access_password):
        if not os.path.exists(self.disk_name):
            raise FileNotFoundError(f"Filesystem {self.disk_name} does not exist.")
        
        # decrypt metadata and filesystem
        self.access_password = access_password
        self.metadata = Metadata.read_metadata(self.access_password)
        self.master_key, self.nonce = FS_Crypto.derive_key(
            self.access_password,
            self.metadata["salt"]
        )
        self._decrypt_filesystem()

        with open(self.disk_name, 'rb') as f:
            try:
                # verify system if it is the system that created this filesystem
                machine_guid = winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"), "MachineGuid")[0]
                identifier = FS_Crypto.get_hash(machine_guid.encode())
                disk_id = f.read(len(self.header) + 16 + 25 + 4)
                if identifier != self.metadata["identifier"] and identifier != disk_id[4:4+16]:
                    raise ValueError("System fingerprint mismatch. This filesystem can only be used on the original computer.")
                
                self.file_table = self.metadata.get("file_table", [])
                self.is_initialized = True
                self.header = disk_id
                
            except Exception as e:
                raise ValueError(f"Failed to decrypt filesystem. Incorrect password or corrupted data: {e}")
        
        self._encrypt_filesystem()
    
    def save_filesystem(self):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        
        # update metadata
        self.metadata["last_modified"] = datetime.now()
        self.metadata["file_count"] = len(self.file_table)
        self.metadata["deleted_count"] = sum(1 for file in self.file_table if file.get("deleted", False))
        Metadata.update_metadata("last_modified", self.metadata["last_modified"])
        Metadata.update_metadata("file_count", self.metadata["file_count"])
        Metadata.update_metadata("deleted_count", self.metadata["deleted_count"])
        Metadata.update_metadata("file_table", self.file_table)
        Metadata.write_metadata(self.access_password)

        # encrypt file system
        if not self._is_encrypted():
            self._encrypt_filesystem()
    
    def _create_filesystem_structure(self):
        with open(self.disk_name, 'wb') as f:
            f.write(self.header)
    
    def _encrypt_filesystem(self):
        with open(self.disk_name, 'rb') as f:
            data = f.read()
        encrypted_data = FS_Crypto.encrypt(data, self.master_key, nonce=self.nonce)
        with open(self.disk_name, 'wb') as f:
            f.write(encrypted_data)

    def _decrypt_filesystem(self):
        with open(self.disk_name, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = FS_Crypto.decrypt(encrypted_data, self.master_key, nonce=self.nonce)
        with open(self.disk_name, 'wb') as f:
            f.write(decrypted_data)

    def _is_encrypted(self) -> bool:
        with open(self.disk_name, 'rb') as f:
            header = f.read(len(self.header))
        return not header.startswith(self.header)

    def import_file(self, file_path, file_password):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist.")
        
        # check for maximum file count
        active_files = sum(1 for file in self.file_table if not file.get("deleted", False))
        if active_files >= self.metadata["max_files"]:
            raise ValueError(f"Maximum file count ({self.metadata['max_files']}) reached.")
        
        # read file data and create file record
        with open(file_path, 'rb') as f:
            file_data = f.read()

        file_stats = os.stat(file_path)
        file_id = str(uuid.uuid4())
        file_name = os.path.basename(file_path)
        file_path_full = os.path.abspath(file_path)
        
        # encrypt file data if password is provided
        file_key = None
        file_nonce = None
        if file_password:
            file_salt = os.urandom(16)
            file_key, file_nonce = FS_Crypto.derive_key(file_password, file_salt)
            file_data = FS_Crypto.encrypt(file_data, file_key, nonce=file_nonce)

        file_position = self._get_next_file_position()
        file_size = len(file_data)
        
        file_record = {
            "id": file_id,
            "filename": file_name,
            "original_path": file_path_full,
            "size": file_size,
            "original_size": len(file_data) if not file_password else file_stats.st_size,
            "created": datetime.fromtimestamp(file_stats.st_ctime),
            "modified": datetime.fromtimestamp(file_stats.st_mtime),
            "accessed": datetime.fromtimestamp(file_stats.st_atime),
            "imported_date": datetime.now(),
            "encrypted": bool(file_password),
            "position": file_position,
            "deleted": False,
            "attributes": {
                "mode": file_stats.st_mode,
                "uid": file_stats.st_uid,
                "gid": file_stats.st_gid
            }
        }
        
        if file_password:
            file_record["encryption"] = {
                "salt": file_salt,
                "nonce": file_nonce
            }
        
        # update metadata
        self.file_table.append(file_record)
        self.metadata["file_count"] += 1
        
        if self._is_encrypted():
            self._decrypt_filesystem()

        with open(self.disk_name, 'r+b') as f:
            f.seek(file_position)
            f.write(file_data)
            
        self.save_filesystem()
        
        return file_id
        
    def export_file(self, file_id, output_path, file_password):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        
        # check if file exists and is not deleted
        file_record = next((f for f in self.file_table if f["id"] == file_id and not f.get("deleted", False)), None)
        if not file_record:
            raise ValueError(f"File with ID {file_id} not found or is deleted.")
        
        if self._is_encrypted():
            self._decrypt_filesystem()

        with open(self.disk_name, 'rb') as f:
            f.seek(file_record["position"])
            file_size = file_record["size"]
            color._print(f"Exporting file {file_record['filename']} of size {file_size} bytes.", color.CORRECT)
            file_data = f.read(file_size)
        
        # decrypt file data if it is encrypted
        if file_record.get("encrypted", False):
            if not file_password:
                raise ValueError("Password required for encrypted file.")
            
            try:
                salt = file_record["encryption"]["salt"]
                nonce = file_record["encryption"]["nonce"]
                file_key, file_nonce = FS_Crypto.derive_key(file_password, salt)
                if nonce != file_nonce:
                    raise ValueError("Invalid password.")
                file_data = FS_Crypto.decrypt(file_data, file_key, nonce=nonce)
            except Exception as e:
                raise ValueError(f"Failed to decrypt file: {e}")
                
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(file_data)
        
        # set file attributes like mode, uid, gid, accessed, modified time to match the original file
        try:
            os.chmod(output_path, file_record["attributes"]["mode"])
            os.utime(output_path, (
                datetime.timestamp(file_record["accessed"]),
                datetime.timestamp(file_record["modified"])
            ))
        except Exception as e:
            color._print(f"Failed to set file attributes: {e}", color.WARNING)
            pass

        self._encrypt_filesystem()
    
    # list files available in MyFS
    def list_files(self, include_deleted: bool = False):
        if not self.is_initialized:
            return []
            
        if include_deleted:
            return self.file_table
        else:
            return [f for f in self.file_table if not f.get("deleted", False)]
    
    # delete a record in MyFS metadata
    def delete_file_soft(self, file_id):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        file_record = next((f for f in self.file_table if f["id"] == file_id and not f.get("deleted", False)), None)
        if not file_record:
            raise ValueError(f"File with ID {file_id} not found or is already deleted.")
            
        file_record["deleted"] = True
        file_record["deleted_date"] = datetime.now()
        
        self.metadata["file_count"] -= 1
        self.metadata["deleted_count"] += 1
        
        self.save_filesystem()
    
    # delete a record in MyFS metadata permanently and remove it from the disk
    def delete_file_permanent(self, file_id):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        file_record = next((f for f in self.file_table if f["id"] == file_id), None)
        if not file_record:
            raise ValueError(f"File with ID {file_id} not found.")

        file_size = file_record.get("size", 0)
        file_position = file_record.get("position", 0)

        if self._is_encrypted():
            self._decrypt_filesystem()

        # reallocate disk space by removing the file data
        with open(self.disk_name, 'rb') as f:
            data = f.read()
        new_data = data[:file_position] + data[file_position + file_size:]
        with open(self.disk_name, 'wb') as f:
            f.write(new_data)

        if not file_record.get("deleted", False):
            self.metadata["file_count"] -= 1
        else:
            self.metadata["deleted_count"] -= 1
            
        self.file_table = [f for f in self.file_table if f["id"] != file_id]
        # recalculate other files' positions after deletion
        self._calculate_file_position(file_size, file_position)
        self.save_filesystem()
    
    # recover a soft-deleted file by marking it as active again in the metadata
    def recover_file(self, file_id):
        if not self.is_initialized:
            raise ValueError("Filesystem is not initialized.")
        file_record = next((f for f in self.file_table if f["id"] == file_id and f.get("deleted", False)), None)
        if not file_record:
            raise ValueError(f"Deleted file with ID {file_id} not found.")
            
        active_files = sum(1 for file in self.file_table if not file.get("deleted", False))
        if active_files >= self.metadata["max_files"]:
            raise ValueError(f"Maximum file count ({self.metadata['max_files']}) reached.")
            
        file_record["deleted"] = False
        file_record.pop("deleted_date", None)
        
        self.metadata["file_count"] += 1
        self.metadata["deleted_count"] -= 1
        
        self.save_filesystem()

    # calculate the next file position in the disk
    def _get_next_file_position(self) -> int:
        with open(self.disk_name, 'rb') as f:
            f.seek(0, os.SEEK_END)
            return f.tell()

    # calculate the position of other records after deleted a file
    def _calculate_file_position(self, file_size: int, file_position: int):
        for file_record in self.file_table:
            if file_record.get("position", 0) > file_position:
                file_record["position"] -= file_size