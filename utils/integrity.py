import os
import inspect
import hashlib
import pickle
import importlib


# SHA256 hash every file in the project directory and its subdirectories
def calculate_file_hash(filepath):
    if not os.path.exists(filepath):
        return ""
    
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        return hashlib.sha256(file_data).hexdigest()
    except Exception:
        return ""

# get all functions in a module and their source codes
def get_module_functions(module):
    return {name: obj for name, obj in inspect.getmembers(module, inspect.isfunction)
            if obj.__module__ == module.__name__}

# get all classes in a module and their source codes
def get_module_classes(module):
    return {name: obj for name, obj in inspect.getmembers(module, inspect.isclass)
            if obj.__module__ == module.__name__}

# scan the project directory for .py files, calculate their hashes,
# and store their functions and classes with source codes in a dictionary
def generate_integrity_data():
    integrity_data = {}
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, project_dir)
                file_hash = calculate_file_hash(filepath)
                module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                module = None
                
                try:
                    module = importlib.import_module(module_path)
                    
                    # get functions and their source codes
                    functions = get_module_functions(module)
                    function_sources = {
                        name: inspect.getsource(func)
                        for name, func in functions.items()
                    }
                    
                    # get classes and their source codes
                    classes = get_module_classes(module)
                    class_sources = {
                        name: inspect.getsource(cls)
                        for name, cls in classes.items()
                    }
                    
                    integrity_data[rel_path] = {
                        'hash': file_hash,
                        'functions': function_sources,
                        'classes': class_sources
                    }
                except (ImportError, ModuleNotFoundError):
                    integrity_data[rel_path] = {
                        'hash': file_hash
                    }
    
    return integrity_data

# write hashes, functions, and classes to a file after serializing the data with pickle
def save_integrity_data(data, output_path):
    try:
        with open(output_path, 'wb') as f:
            pickle.dump(data, f)
    except Exception as e:
        print(f"Error saving integrity data: {e}")

def load_integrity_data(input_path):
    if not os.path.exists(input_path):
        return None
    
    try:
        with open(input_path, 'rb') as f:
            return pickle.load(f)
    except Exception:
        return None

# verify hashes
def verify_file_integrity(filepath, stored_data):
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rel_path = os.path.relpath(filepath, project_dir)
    
    if rel_path not in stored_data:
        return False, f"File {rel_path} not found in integrity data"
    
    current_hash = calculate_file_hash(filepath)
    if current_hash != stored_data[rel_path]['hash']:
        return False, f"File {rel_path} has been modified"
    
    module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
    
    try:
        module = importlib.import_module(module_path)
        
        if 'functions' in stored_data[rel_path]:
            for name, stored_source in stored_data[rel_path]['functions'].items():
                if hasattr(module, name):
                    func = getattr(module, name)
                    if inspect.isfunction(func):
                        try:
                            current_source = inspect.getsource(func)
                            if current_source != stored_source:
                                return False, f"Function {name} in {rel_path} has been modified"
                        except Exception:
                            pass
        
        if 'classes' in stored_data[rel_path]:
            for name, stored_source in stored_data[rel_path]['classes'].items():
                if hasattr(module, name):
                    cls = getattr(module, name)
                    if inspect.isclass(cls):
                        try:
                            current_source = inspect.getsource(cls)
                            if current_source != stored_source:
                                return False, f"Class {name} in {rel_path} has been modified"
                        except Exception:
                            pass
    except (ImportError, ModuleNotFoundError):
        pass
    
    return True, ""


def verify_integrity():
    integrity_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                 'integrity.dat')
    
    # initialize integrity data if it does not exist
    stored_data = load_integrity_data(integrity_file)
    if stored_data is None:
        print("Integrity data not found. Generating new integrity data...")
        stored_data = generate_integrity_data()
        save_integrity_data(stored_data, integrity_file)
        return True
    
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    all_valid = True
    
    # scan the project directory for .py files and verify their integrity
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, project_dir)
                is_valid, message = verify_file_integrity(filepath, stored_data)
                
                if not is_valid:
                    print(f"Integrity violation: {message}")
                    all_valid = False
    
    return all_valid

# copy original files from the backup directory to the project directory
def restore_original_files():
    backup_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             'backup')
    
    if not os.path.exists(backup_dir):
        print("Backup directory not found. Cannot restore files.")
        return
    
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    for root, _, files in os.walk(backup_dir):
        for file in files:
            if file.endswith('.py'):
                backup_file = os.path.join(root, file)
                rel_path = os.path.relpath(backup_file, backup_dir)
                target_file = os.path.join(project_dir, rel_path)

                os.makedirs(os.path.dirname(target_file), exist_ok=True)

                try:
                    with open(backup_file, 'rb') as src, open(target_file, 'wb') as dst:
                        dst.write(src.read())
                    print(f"Restored {rel_path}")
                except Exception as e:
                    print(f"Failed to restore {rel_path}: {e}")