#!/usr/bin/env python3
"""
AutoReverse Plugin Installation Script for Windows IDA Pro 9.0
Automatically installs the plugin to the correct IDA Pro directory
"""

import os
import sys
import shutil
import platform
import tempfile
from pathlib import Path

def find_ida_pro_9_installation():
    """Find IDA Pro 9.0 installation directory"""
    possible_paths = [
        Path(r"C:\Program Files\IDA Professional 9.0"),
        Path(r"C:\Program Files (x86)\IDA Professional 9.0"),
        Path(r"C:\Program Files\IDA Pro 9.0"),
        Path(r"C:\Program Files (x86)\IDA Pro 9.0"),
        Path(r"C:\IDA Professional 9.0"),
        Path(r"C:\IDA Pro 9.0"),
    ]
    
    for path in possible_paths:
        if path.exists() and (path / "ida.exe").exists():
            return path
    
    return None

def get_ida_plugins_dir():
    """Get the IDA Pro plugins directory"""
    ida_root = find_ida_pro_9_installation()
    if ida_root:
        return ida_root / "plugins"
    return None

def install_plugin():
    """Install the plugin files"""
    print("AutoReverse Plugin Installer for Windows IDA Pro 9.0")
    print("=" * 50)
    
    # Check if running on Windows
    if platform.system() != "Windows":
        print("Error: This installer is for Windows only")
        return False
    
    # Check if running as administrator
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("Warning: You may need to run as administrator to install to Program Files")
    except:
        pass
    
    # Get IDA plugins directory
    plugins_dir = get_ida_plugins_dir()
    
    if not plugins_dir:
        print("Error: Could not find IDA Pro 9.0 installation")
        print("Please install manually by copying the plugin files to your IDA plugins directory")
        print("\nTried these locations:")
        possible_paths = [
            r"C:\Program Files\IDA Professional 9.0",
            r"C:\Program Files (x86)\IDA Professional 9.0",
            r"C:\Program Files\IDA Pro 9.0",
            r"C:\Program Files (x86)\IDA Pro 9.0",
        ]
        for path in possible_paths:
            print(f"  {path}")
        return False
    
    print(f"Found IDA Pro 9.0 at: {plugins_dir.parent}")
    print(f"Target plugins directory: {plugins_dir}")
    
    # Check if directory exists
    if not plugins_dir.exists():
        print(f"Error: Plugins directory does not exist: {plugins_dir}")
        return False
    
    # Check if we have write permissions
    try:
        test_file = plugins_dir / "test_write.tmp"
        test_file.write_text("test")
        test_file.unlink()
    except Exception as e:
        print(f"Error: Cannot write to plugins directory: {e}")
        print("Please run as administrator or check permissions")
        return False
    
    # Get current directory (where installer is located)
    current_dir = Path(__file__).parent
    target_dir = plugins_dir / "AutoReverse"
    
    # CRITICAL: Check if we're running from the target directory
    # This prevents the installer from deleting itself!
    running_from_target = False
    try:
        if current_dir.resolve() == target_dir.resolve():
            running_from_target = True
            print("Detected: Running installer from target directory")
    except:
        pass
    
    # Define files and directories to install
    files_to_install = [
        "auto_reverse.py",
        "README.md",
        "LICENSE", 
        "requirements.txt"
    ]
    
    directories_to_install = [
        "modules"
    ]
    
    # Check if required files exist
    missing_files = []
    for file in files_to_install:
        if not (current_dir / file).exists():
            missing_files.append(file)
    
    for directory in directories_to_install:
        if not (current_dir / directory).exists():
            missing_files.append(directory)
    
    if missing_files:
        print(f"Error: Missing required files/directories: {', '.join(missing_files)}")
        return False
    
    # If we're running from the target directory, we need to be more careful
    if running_from_target:
        print("Installing in-place (updating existing installation)...")
        
        # Just verify all files are present and report success
        print("Plugin files are already in the correct location!")
        print("Verifying installation...")
        
        # Verify all required files exist
        all_present = True
        for file in files_to_install:
            if not (target_dir / file).exists():
                print(f"Missing: {file}")
                all_present = False
        
        for directory in directories_to_install:
            if not (target_dir / directory).exists():
                print(f"Missing: {directory}/")
                all_present = False
            else:
                # Check for module files
                module_files = ["__init__.py", "config_manager.py", "gemini_client.py", 
                               "struct_analyzer.py", "type_setter.py", "ui_manager.py", "variable_renamer.py"]
                for module_file in module_files:
                    if not (target_dir / directory / module_file).exists():
                        print(f"Missing: {directory}/{module_file}")
                        all_present = False
        
        if all_present:
            print("All plugin files are present and accounted for!")
            # Show success message
            print("\n" + "=" * 50)
            print("INSTALLATION VERIFIED!")
            print("=" * 50)
            print("\nPlugin is ready to use:")
            print("1. Start IDA Pro 9.0")
            print("2. Open any binary file")
            print("3. Look for 'AutoReverse' in the Edit menu")
            print("4. Configure your Gemini API key in the plugin settings")
            print(f"\nPlugin location: {target_dir}")
            return True
        else:
            print("Some files are missing. Installation may be incomplete.")
            return False
    
    # Normal installation (not running from target directory)
    print("Installing plugin to target directory...")
    
    # Remove existing installation if it exists and we're not running from it
    if target_dir.exists():
        print(f"Removing existing installation at {target_dir}")
        try:
            shutil.rmtree(target_dir)
        except Exception as e:
            print(f"Error removing existing installation: {e}")
            print("This might happen if IDA Pro is currently running with the plugin loaded.")
            print("Please close IDA Pro and try again.")
            return False
    
    # Create target directory
    try:
        target_dir.mkdir()
        print(f"Created plugin directory: {target_dir}")
    except Exception as e:
        print(f"Error creating plugin directory: {e}")
        return False
    
    # Install files
    print("\nInstalling plugin files...")
    installed_items = []
    
    try:
        # Copy files
        for file in files_to_install:
            src = current_dir / file
            dst = target_dir / file
            print(f"Installing {file}...")
            shutil.copy2(src, dst)
            installed_items.append(dst)
        
        # Copy directories
        for directory in directories_to_install:
            src = current_dir / directory
            dst = target_dir / directory
            print(f"Installing {directory}/ directory...")
            shutil.copytree(src, dst)
            installed_items.append(dst)
        
        print(f"\nSuccessfully installed {len(installed_items)} items!")
        
        # Show next steps
        print("\n" + "=" * 50)
        print("INSTALLATION COMPLETE!")
        print("=" * 50)
        print("\nNext steps:")
        print("1. Start IDA Pro 9.0")
        print("2. Open any binary file")
        print("3. Look for 'AutoReverse' in the Edit menu")
        print("4. Configure your Gemini API key in the plugin settings")
        print("\nPlugin installed to:")
        print(f"  {target_dir}")
        print("\nFor troubleshooting, check the plugin files are in:")
        print(f"  {target_dir}")
        
        return True
        
    except Exception as e:
        print(f"Error during installation: {e}")
        # Clean up on failure (but only if we're not running from target dir)
        if target_dir.exists() and not running_from_target:
            try:
                shutil.rmtree(target_dir)
            except:
                pass
        return False

def uninstall_plugin():
    """Uninstall the plugin"""
    print("AutoReverse Plugin Uninstaller")
    print("=" * 30)
    
    plugins_dir = get_ida_plugins_dir()
    
    if not plugins_dir:
        print("Error: Could not find IDA Pro 9.0 installation")
        return False
    
    target_dir = plugins_dir / "AutoReverse"
    current_dir = Path(__file__).parent
    
    # Check if we're trying to uninstall from the target directory
    running_from_target = False
    try:
        if current_dir.resolve() == target_dir.resolve():
            running_from_target = True
    except:
        pass
    
    if running_from_target:
        print("Error: Cannot uninstall while running from the plugin directory!")
        print("Please run the uninstaller from a different location.")
        return False
    
    if not target_dir.exists():
        print("Plugin is not installed")
        return False
    
    try:
        shutil.rmtree(target_dir)
        print("Successfully uninstalled AutoReverse plugin")
        return True
    except Exception as e:
        print(f"Error uninstalling plugin: {e}")
        return False

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        success = uninstall_plugin()
    else:
        success = install_plugin()
    
    if not success:
        print("\nOperation failed!")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("\nOperation completed successfully!")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main() 