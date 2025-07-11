"""
Configuration Manager for AutoReverse Plugin
Handles API keys and plugin settings
"""

import os
import json
from pathlib import Path
import ida_kernwin

class ConfigManager:
    def __init__(self):
        self.config_file = Path.home() / ".autoreverse_config.json"
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
        
        return {
            "api_key": "",
            "model": "gemini-pro",
            "temperature": 0.7,
            "max_tokens": 4096,
            "show_prompts": False
        }
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get_api_key(self):
        """Get the API key"""
        return self.config.get("api_key", "")
    
    def set_api_key(self, api_key):
        """Set the API key"""
        self.config["api_key"] = api_key
        return self.save_config()
    
    def get_model(self):
        """Get the model name"""
        return self.config.get("model", "gemini-pro")
    
    def set_model(self, model):
        """Set the model name"""
        self.config["model"] = model
        return self.save_config()
    
    def get_temperature(self):
        """Get the temperature setting"""
        return self.config.get("temperature", 0.7)
    
    def set_temperature(self, temperature):
        """Set the temperature setting"""
        self.config["temperature"] = temperature
        return self.save_config()
    
    def get_max_tokens(self):
        """Get the max tokens setting"""
        return self.config.get("max_tokens", 4096)
    
    def set_max_tokens(self, max_tokens):
        """Set the max tokens setting"""
        self.config["max_tokens"] = max_tokens
        return self.save_config()
    
    def get_all_settings(self):
        """Get all settings"""
        return self.config.copy()
    
    def update_settings(self, settings):
        """Update multiple settings"""
        self.config.update(settings)
        return self.save_config()
    
    def get_show_prompts(self):
        """Get the show prompts setting"""
        return self.config.get("show_prompts", False)
    
    def set_show_prompts(self, show_prompts):
        """Set the show prompts setting"""
        self.config["show_prompts"] = show_prompts
        return self.save_config() 