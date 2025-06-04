import os
import sys
import getpass
from utils.fs_manager import MyFSManager
from utils.fs_metadata import Metadata
from utils.color import Color
from utils.integrity import verify_integrity, restore_original_files


DISK_NAME = "MyFS.DRI"
color = Color()

def main():
    print("Welcome to MyFileSystem (MyFS)!")
    
    if not os.path.exists(DISK_NAME):
        color._print("Creating new filesystem...", color.CORRECT)

        # check if USB drive is available and metadata file exists in it
        if not Metadata.check_usb():
            color._print("USB drive not found! Please insert the USB drive and try again.", color.WRONG)
            sys.exit(1)
        if not Metadata.check_metadata(Metadata.check_usb()):
            color._print("Metadata file not found! Creating new one...", color.WARNING)
            with open(Metadata.metadata_path, 'w') as f:
                f.write("")

        access_password = getpass.getpass("Create access password: ")
        confirm_password = getpass.getpass("Confirm access password: ")

        if access_password != confirm_password:
            color._print("Passwords do not match! Exiting...", color.WRONG)
            sys.exit(1)

        # initialize filesystem
        fs_manager = MyFSManager()
        fs_manager.initialize_filesystem(access_password)
        color._print("Filesystem created successfully.", color.CORRECT)
    else:
        if not Metadata.check_usb():
            color._print("USB drive not found! Please insert the USB drive and try again.", color.WRONG)
            sys.exit(1)
        if not Metadata.check_metadata(Metadata.check_usb()):
            color._print("Metadata file not found! Please create a new filesystem.", color.WRONG)
            sys.exit(1)
        
        # load existing filesystem
        access_password = getpass.getpass("Enter access password: ")
        try:
            fs_manager = MyFSManager()
            fs_manager.load_filesystem(access_password)
            color._print("Filesystem loaded successfully.", color.CORRECT)
        except Exception as e:
            color._print(f"Error loading filesystem: {e}", color.WRONG)
            color._print("Please check your access password and try again.", color.WRONG)
            sys.exit(1)
    
    while True:
        print("""MyFS Commands:
        1. List files
        2. Import file
        3. Export file
        4. Soft-delete file
        5. Permanently delete file
        6. Recover deleted file
        7. Verify password
        8. Change password
        9. Exit""")
        
        choice = input("Enter choice: ")
        
        # list files available in MyFS
        if choice == '1':
            files = fs_manager.list_files()
            if not files:
                color._print("No files found in MyFS.", color.WARNING)
            else:
                print("\nFiles in MyFS:")
                for i, file_info in enumerate(files, 1):
                    status = "Deleted" if file_info.get("deleted", False) else "Active"
                    print(f"{i}. {file_info['filename']} ({file_info['size']} bytes) - {status}")
        
        # import file into MyFS
        elif choice == '2':
            filepath = input("Enter file path to import: ")
            if not os.path.exists(filepath):
                color._print("File does not exist. Please check the path and try again.", color.WRONG)
                continue
                
            use_encryption = input("Encrypt this file? (y/n): ").lower() == 'y'
            file_password = None
            if use_encryption:
                file_password = getpass.getpass("Enter file encryption password: ")
                
            try:
                fs_manager.import_file(filepath, file_password)
                color._print("File imported successfully.", color.CORRECT)
            except Exception as e:
                color._print(f"Error importing file: {e}", color.WRONG)
                continue
        
        # export file from MyFS
        elif choice == '3':
            # get list of available files
            files = fs_manager.list_files(include_deleted=False)
            if not files:
                color._print("No files to export.", color.WARNING)
                continue
            for i, file_info in enumerate(files, 1):
                print(f"{i}. {file_info['filename']}")
            
            # select file to export with index
            idx = int(input("Enter file number to export: ")) - 1
            if idx < 0 or idx >= len(files):
                color._print("Invalid file number.", color.WRONG)
                continue
            
            # print its original path
            color._print(f"Original path: {files[idx]['original_path']}", color.CORRECT)
            output_path = input("Enter destination path: ")
            
            # decrypt if encrypted
            file_password = None
            if files[idx].get("encrypted", False):
                file_password = getpass.getpass("Enter file encryption password: ")
            
            try:
                fs_manager.export_file(files[idx]['id'], output_path, file_password)
                color._print("File exported successfully.", color.CORRECT)
            except Exception as e:
                color._print(f"Error exporting file: {e}", color.WRONG)
                continue
        
        # delete file (soft or permanent)
        elif choice == '4' or choice == '5':
            permanent = (choice == '5')
            files = fs_manager.list_files(include_deleted=(not permanent))
            if not files:
                color._print("No files to delete.", color.WARNING)
                continue
            for i, file_info in enumerate(files, 1):
                status = "Deleted" if file_info.get("deleted", False) else "Active"
                print(f"{i}. {file_info['filename']} - {status}")
                
            idx = int(input("Enter file number to delete: ")) - 1
            if idx < 0 or idx >= len(files):
                color._print("Invalid file number.", color.WRONG)
                continue
            
            # delete file
            if permanent:
                fs_manager.delete_file_permanent(files[idx]['id'])
                color._print("File permanently deleted.", color.CORRECT)
            else:
                fs_manager.delete_file_soft(files[idx]['id'])
                color._print("File soft-deleted.", color.CORRECT)
        
        # recover deleted file (soft-deleted)
        elif choice == '6':
            # get list of deleted files with its metadata
            files = fs_manager.list_files(include_deleted=True)
            deleted_files = [f for f in files if f.get("deleted", False)]
            if not deleted_files:
                color._print("No deleted files to recover.", color.WARNING)
                continue
            for i, file_info in enumerate(deleted_files, 1):
                print(f"{i}. {file_info['filename']}")
                
            idx = int(input("Enter file number to recover: ")) - 1
            if idx < 0 or idx >= len(deleted_files):
                color._print("Invalid file number.", color.WRONG)
                continue
                
            try:
                fs_manager.recover_file(deleted_files[idx]['id'])
                color._print("File recovered successfully.", color.CORRECT)
            except Exception as e:
                color._print(f"Error recovering file: {e}", color.WRONG)
                continue
        
        # verify access password
        elif choice == '7':
            password = getpass.getpass("Enter access password to verify: ")
            try:
                if fs_manager.verify_password(password):
                    color._print("Password verified successfully.", color.CORRECT)
                else:
                    color._print("Incorrect password. Please try again.", color.WRONG)
            except Exception as e:
                color._print(f"Error verifying password: {e}", color.WRONG)
                continue
        
        # change access password
        elif choice == '8':
            old_password = getpass.getpass("Enter current access password: ")
            if not fs_manager.verify_password(old_password):
                color._print("Incorrect password. Cannot change password.", color.WRONG)
                continue
            
            new_password = getpass.getpass("Enter new access password: ")
            confirm_new_password = getpass.getpass("Confirm new access password: ")
            
            if new_password != confirm_new_password:
                color._print("Passwords do not match. Please try again.", color.WRONG)
                continue
            
            try:
                fs_manager.change_password(old_password, new_password)
                color._print("Password changed successfully.", color.CORRECT)
            except Exception as e:
                color._print(f"Error changing password: {e}", color.WRONG)

        # exit MyFS
        elif choice == '9':
            color._print("Exiting MyFS. Goodbye!", color.CORRECT)
            fs_manager.save_filesystem()
            break
            
        else:
            color._print("Invalid choice. Please try again.", color.WRONG)


if __name__ == "__main__":
    # verify integrity of the project in real-time
    if not verify_integrity():
        color._print("WARNING: The application has been modified! Restoring original version...", color.WRONG)
        # restore original files in backup/ if failed
        restore_original_files()
        color._print("Application has been restored. Please restart the application.", color.WARNING)
        sys.exit(1)
    
    main()